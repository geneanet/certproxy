# -*- coding: utf-8 -*-

import requests
import os
import subprocess
import socket
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from .tools import load_certificate, load_or_create_privatekey, rsa_key_fingerprint, writefile, readfile, load_privatekey, impersonation, list_certificates

import logging

logger = logging.getLogger('certproxy.client')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class Client:

    def __init__(self, server, private_key_file, certificate_file, crt_path, subject, certificates_config):
        self.server = server
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.crt_path = crt_path
        self.subject = subject
        self.certificates_config = certificates_config

        self.pkey = load_or_create_privatekey(private_key_file)
        if os.path.isfile(certificate_file):
            self.cert = load_certificate(certificate_file)
        else:
            self.cert = None

    def requestauth(self):
        # Create a CSR
        subject_attrs = []
        cn_already_set = False
        for attr in self.subject:
            if attr.oid == NameOID.COMMON_NAME:
                cn_already_set = True
            subject_attrs.append(attr)
        if not cn_already_set:
            subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, socket.getfqdn()))
        subject = x509.Name(subject_attrs)

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(
            private_key=self.pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Ask for signature
        body = {
            'csr': csr.public_bytes(serialization.Encoding.PEM).decode()
        }
        response = requests.post(
            url=self.server + '/authorize',
            json=body,
            verify=False
        )

        if response.status_code == 200 or response.status_code == 202:
            data = response.json()
            if data['status'] == 'pending':
                logger.info("Authorization requested (key fingerprint: %s).", rsa_key_fingerprint(self.pkey.public_key()))
            elif data['status'] == 'authorized':
                with open(self.certificate_file, 'w') as f:
                    f.write(data['crt'])
                logger.info("Client authorized.")
        elif response.status_code == 500:
            data = response.json()
            logger.error('An error occured on CertProxy server while processing the request: %s', data['message'])
        else:
            logger.error('CertProxy server replied with an unexpected error code: %d (%s)', response.status_code, response.reason)

    def requestcert(self, domain, force=False, renew_margin=30, force_renew=False):
        certificate_file = os.path.join(self.crt_path, '{}.crt'.format(domain))
        chain_file = os.path.join(self.crt_path, '{}-chain.crt'.format(domain))
        key_file = os.path.join(self.crt_path, '{}.key'.format(domain))

        # Try to load existing private key
        if os.path.isfile(key_file):
            try:
                key = load_privatekey(key_file)
            except Exception:
                logger.error('Unable to load private key %s', key_file)
                key = None
        else:
            key = None

        # Try to load existing certificate
        if os.path.isfile(certificate_file):
            try:
                crt = load_certificate(certificate_file)
            except Exception:
                logger.error('Unable to load certificate %s', certificate_file)
                crt = None
        else:
            crt = None

        # Try to load existing chain
        if os.path.isfile(chain_file):
            try:
                chain = readfile(chain_file, binary=True)
            except Exception:
                logger.error('Unable to load certificate chain %s', chain_file)
                chain = None
        else:
            chain = None

        # Flag to determine if a new certificate should be fetched
        fetch = True

        # If the key correspond to the certificate
        if crt and key and crt.public_key().public_numbers() == key.public_key().public_numbers():
            # If the certificate is valid and before renew period
            if crt.not_valid_before < datetime.utcnow() and crt.not_valid_after > datetime.utcnow() + timedelta(days=renew_margin):
                # Return the cert and its key
                logger.info('The certificate for %s is still valid and not in the renew margin', domain)

                # If the chain is available, eveything is OK, it is not necessary to fetch a new cert
                if chain is not None:
                    fetch = False
                else:
                    logger.error('The certificate chain for %s is missing')
            else:
                logger.info('The certificate for %s should be renewed (expires %s UTC, renew after %s UTC)', domain, crt.not_valid_after, crt.not_valid_after - timedelta(days=renew_margin))
        elif crt and key:
            logger.error('The key %s does not correspond to the certificate %s', key_file, certificate_file)

        # Always fetch if the fetch force is given
        fetch = force | fetch

        # If we should fetch the certificate
        if fetch:
            logger.info('Fetching certificate for %s', domain)
            response = requests.get(
                url=self.server + '/cert/' + domain,
                cert=(self.certificate_file, self.private_key_file),
                verify=False,
                params={'force_renew': 'true' if force_renew else 'false'}
            )

            if response.status_code == 200:
                data = response.json()

                writefile(certificate_file, data['crt'])
                writefile(chain_file, data['chain'])
                writefile(key_file, data['key'])

                newcrt = load_certificate(certificate_file)
                logger.info('Certificate for %s fetched (expires %s UTC, renew after %s UTC)', domain, newcrt.not_valid_after, newcrt.not_valid_after - timedelta(days=renew_margin))

                self.execute_actions(domain)

                return True

            elif response.status_code >= 400 and response.status_code < 500:
                data = response.json()
                logger.error('CertProxy server could not process the request: %s', data['message'])
                return False

            elif response.status_code == 500:
                data = response.json()
                logger.error('An error occured on CertProxy server while processing the request: %s', data['message'])
                return False

            else:
                logger.error('CertProxy server replied with an unexpected error code: %d (%s)', response.status_code, response.reason)
                return False

        else:
            return False

    def execute_actions(self, domain):
        # Find a config matching the domain
        certificate_file = os.path.join(self.crt_path, '{}.crt'.format(domain))
        chain_file = os.path.join(self.crt_path, '{}-chain.crt'.format(domain))
        key_file = os.path.join(self.crt_path, '{}.key'.format(domain))

        certconfig = self.certificates_config.match(domain, certificate_file=certificate_file, chain_file=chain_file, key_file=key_file)

        # If we have a matching config
        if certconfig:
            logger.debug('Domain %s matches pattern %s', domain, certconfig.pattern)

            # Deploy the certificate if requested
            if certconfig.deploy_crt:
                path = certconfig.deploy_crt.path
                logger.info('Deploying certificate into %s', path)
                writefile(
                    path=path,
                    owner=certconfig.deploy_crt.owner,
                    group=certconfig.deploy_crt.group,
                    mode=certconfig.deploy_crt.mode,
                    data=readfile(certificate_file),
                )

            # Deploy the private key if requested
            if certconfig.deploy_key:
                path = certconfig.deploy_key.path
                logger.info('Deploying private key into %s', path)
                writefile(
                    path=path,
                    owner=certconfig.deploy_key.owner,
                    group=certconfig.deploy_key.group,
                    mode=certconfig.deploy_key.mode,
                    data=readfile(key_file),
                )

            # Deploy the key chain if requested
            if certconfig.deploy_chain:
                path = certconfig.deploy_chain.path
                logger.info('Deploying chain into %s', path)
                writefile(
                    path=path,
                    owner=certconfig.deploy_chain.owner,
                    group=certconfig.deploy_chain.group,
                    mode=certconfig.deploy_chain.mode,
                    data=readfile(chain_file),
                )

            # Deploy the full chain (certificate + chain) if requested
            if certconfig.deploy_full_chain:
                path = certconfig.deploy_full_chain.path
                logger.info('Deploying full chain into %s', path)
                writefile(
                    path=path,
                    owner=certconfig.deploy_full_chain.owner,
                    group=certconfig.deploy_full_chain.group,
                    mode=certconfig.deploy_full_chain.mode,
                    data=readfile(certificate_file) + '\n' + readfile(chain_file),
                )

            # Execute a command if requested
            if certconfig.execute:
                command = certconfig.execute.command
                logger.info('Executing command: %s', command)
                returncode = subprocess.call(
                    args=command,
                    shell=True,
                    preexec_fn=impersonation(user=certconfig.execute.user, group=certconfig.execute.group, workdir=certconfig.execute.workdir),
                    timeout=certconfig.execute.timeout
                )
                logger.debug('Command returned code %d', returncode)

        else:
            logger.debug('No configuration found for domain %s', domain)

    def list_certificates(self):
        return list_certificates(self.crt_path)

    def delete_certificate(self, domain):
        certificate_file = os.path.join(self.crt_path, '{}.crt'.format(domain))
        chain_file = os.path.join(self.crt_path, '{}-chain.crt'.format(domain))
        key_file = os.path.join(self.crt_path, '{}.key'.format(domain))

        if os.path.isfile(certificate_file):
            logger.debug('Deleting %s', certificate_file)
            os.unlink(certificate_file)

        if os.path.isfile(chain_file):
            logger.debug('Deleting %s', chain_file)
            os.unlink(chain_file)

        if os.path.isfile(key_file):
            logger.debug('Deleting %s', key_file)
            os.unlink(key_file)
