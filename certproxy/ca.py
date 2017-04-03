# -*- coding: utf-8 -*-

import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .tools import load_or_create_privatekey, sign_certificate_request, load_or_create_ca_certificate, rsa_key_fingerprint, x509_cert_fingerprint, load_or_create_crl, load_certificate, update_crl, revoked_cert

import logging

logger = logging.getLogger('certproxy.ca')

class CA:
    def __init__(self, private_key_file, certificate_file, crl_file, crt_path, csr_path, subject = None):
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.crl_file = crl_file
        self.crt_path = crt_path
        self.csr_path = csr_path

        self.subject = subject if subject else { 'commonName': 'CertProxy CA' }

        self.pkey = load_or_create_privatekey(self.private_key_file)
        self.cert = load_or_create_ca_certificate(self.certificate_file, self.subject, self.pkey)
        self.crl  = load_or_create_crl(self.crl_file, self.cert, self.pkey)

    def list_hosts(self):
        hosts = {}

        for csr_file in os.listdir(self.csr_path):
            with open(os.path.join(self.csr_path, csr_file), 'rb') as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
                hosts[csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = {
                    'key_fingerprint': rsa_key_fingerprint(csr.public_key()),
                    'cert_fingerprint': None,
                    'status': 'pending',
                }

        for crt_file in os.listdir(self.crt_path):
            with open(os.path.join(self.crt_path, crt_file), 'rb') as f:
                crt = x509.load_pem_x509_certificate(f.read(), default_backend())
                revoked = revoked_cert(crt, self.crl)
                if revoked:
                    status = 'revoked'
                else:
                    status = 'authorized'
                hosts[crt.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = {
                    'key_fingerprint': rsa_key_fingerprint(crt.public_key()),
                    'cert_fingerprint': x509_cert_fingerprint(crt),
                    'status': status,
                }

        return hosts

    def authorize_host(self, host):
        csr_file = os.path.join(self.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.crt_path, "%s.crt" % (host))

        sign_certificate_request(csr_file, crt_file, self.cert, self.pkey)

    def revoke_host(self, host):
        crt = load_certificate(os.path.join(self.crt_path, "%s.crt" % (host)))
        if revoked_cert(crt, self.crl):
            return
        self.crl = update_crl(self.crl_file, [crt], self.cert, self.pkey)

    def clean_hosts(self):
        hosts =  self.list_hosts()

        for host, hostinfos in hosts.items():
            if hostinfos['status'] in ('pending', 'revoked'):
                csr_file = os.path.join(self.csr_path, "%s.csr" % (host))
                crt_file = os.path.join(self.crt_path, "%s.crt" % (host))

                if os.path.isfile(csr_file):
                    os.remove(csr_file)

                if os.path.isfile(crt_file):
                    os.remove(crt_file)
