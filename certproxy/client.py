#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import os
import socket
from munch import Munch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from .tools import load_certificate, load_or_create_privatekey, rsa_key_fingerprint, writefile

import logging

logger = logging.getLogger('certproxy.client')
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Client:
    def __init__(self, server, private_key_file, certificate_file, crt_path, subject = None):
        self.server = server
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.crt_path = crt_path

        self.subject = subject if subject else {}

        self.pkey = load_or_create_privatekey(private_key_file)
        if os.path.isfile(certificate_file):
            self.cert = load_certificate(certificate_file)
        else:
            self.cert = None

    def requestauth(self):
        # Create a CSR
        subject = self.subject

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, socket.getfqdn()),
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject.countryName),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.stateOrProvinceName),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organizationName),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizationalUnitName),
        ])).sign(
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

    def requestcert(self, domain):
        response = requests.get(
            url=self.server + '/cert/' + domain,
            cert=(self.certificate_file, self.private_key_file),
            verify=False
        )
        data = Munch(response.json())

        writefile(os.path.join(self.crt_path, '{}.crt'.format(domain)), data.crt)
        writefile(os.path.join(self.crt_path, '{}-chain.crt'.format(domain)), data.chain)
        writefile(os.path.join(self.crt_path, '{}.key'.format(domain)), data.key)
