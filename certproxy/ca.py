# -*- coding: utf-8 -*-

import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from .tools import load_or_create_privatekey, sign_certificate_request, load_or_create_ca_certificate, rsa_key_fingerprint, x509_cert_fingerprint, load_or_create_crl, load_certificate, update_crl, revoked_cert

import logging

logger = logging.getLogger('certproxy.ca')

class CA:
    def __init__(self, config):
        self.config = config # TODO : Check config keys

        self.pkey = load_or_create_privatekey(self.config.server.ca.private_key)
        self.cert = load_or_create_ca_certificate(self.config.server.ca.certificate, self.config.server.ca.subject, self.pkey)
        self.crl  = load_or_create_crl(self.config.server.ca.crl, self.cert, self.pkey)

    def list_hosts(self):
        hosts = {}

        for csr_file in os.listdir(self.config.server.ca.csr_path):
            with open(os.path.join(self.config.server.ca.csr_path, csr_file), 'rb') as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
                hosts[csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value] = {
                    'key_fingerprint': rsa_key_fingerprint(csr.public_key()),
                    'cert_fingerprint': None,
                    'status': 'pending',
                }

        for crt_file in os.listdir(self.config.server.ca.crt_path):
            with open(os.path.join(self.config.server.ca.crt_path, crt_file), 'rb') as f:
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
        csr_file = os.path.join(self.config.server.ca.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.config.server.ca.crt_path, "%s.crt" % (host))

        sign_certificate_request(csr_file, crt_file, self.cert, self.pkey)

    def revoke_host(self, host):
        crt = load_certificate(os.path.join(self.config.server.ca.crt_path, "%s.crt" % (host)))
        if revoked_cert(crt, self.crl):
            return
        self.crl = update_crl(self.config.server.ca.crl, crt, self.cert, self.pkey)

    def clean_hosts(self):
        hosts =  self.list_hosts()

        for host, hostinfos in hosts.items():
            if hostinfos['status'] in ('pending', 'revoked'):
                csr_file = os.path.join(self.config.server.ca.csr_path, "%s.csr" % (host))
                crt_file = os.path.join(self.config.server.ca.crt_path, "%s.crt" % (host))

                if os.path.isfile(csr_file):
                    os.remove(csr_file)

                if os.path.isfile(crt_file):
                    os.remove(crt_file)
