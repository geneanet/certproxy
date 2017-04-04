# -*- coding: utf-8 -*-

import requests
import os
import socket
from munch import Munch
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from .tools import load_certificate, load_or_create_privatekey, rsa_key_fingerprint, writefile, readfile, load_privatekey

import logging

logger = logging.getLogger('certproxy.client')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class Client:

    def __init__(self, server, private_key_file, certificate_file, crt_path, subject):
        self.server = server
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.crt_path = crt_path

        self.subject = subject

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
        data = Munch(response.json())

        if data.status == 'pending':
            print("Authorization requested (key fingerprint: %s)." % rsa_key_fingerprint(self.pkey.public_key()))
        elif data.status == 'authorized':
            with open(self.certificate_file, 'w') as f:
                f.write(data.crt)
            print("Client authorized.")

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
            data = Munch(response.json())

            writefile(certificate_file, data.crt)
            writefile(chain_file, data.chain)
            writefile(key_file, data.key)

            newcrt = load_certificate(certificate_file)
            logger.info('Certificate for %s fetched (expires %s UTC, renew after %s UTC)', domain, newcrt.not_valid_after, newcrt.not_valid_after - timedelta(days=renew_margin))

            return True
        else:
            return False
