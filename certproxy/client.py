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
    def __init__(self, config):
        self.config = config # TODO : Check config keys

        self.pkey = load_or_create_privatekey(self.config.client.private_key)
        if os.path.isfile(self.config.client.certificate):
            self.cert = load_certificate(self.config.client.certificate)
        else:
            self.cert = None

    def requestauth(self):
        # Create a CSR
        subject = self.config.client.subject

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
            url=self.config.client.server + '/authorize',
            json=body,
            verify=False
        )
        data = Munch(response.json())

        if data.status == 'pending':
            print("Authorization requested (key fingerprint: %s)." % rsa_key_fingerprint(self.pkey.public_key()))
        elif data.status == 'authorized':
            with open(self.config.client.certificate, 'w') as f:
                f.write(data.crt)
            print("Client authorized.")

    def requestcert(self, domain):
        response = requests.get(
            url=self.config.client.server + '/cert/' + domain,
            cert=(self.config.client.certificate, self.config.client.private_key),
            verify=False
        )
        data = Munch(response.json())

        writefile(os.path.join(self.config.client.crt_path, '{}.crt'.format(domain)), data.crt)
        writefile(os.path.join(self.config.client.crt_path, '{}-chain.crt'.format(domain)), data.chain)
        writefile(os.path.join(self.config.client.crt_path, '{}.key'.format(domain)), data.key)
