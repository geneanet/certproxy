#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tornado.httpclient
import os
import socket
import json
from munch import Munch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import logging

logger = logging.getLogger('certproxy.client')

class Client:
    def __init__(self, config):
        self.config = config # TODO : Check config keys

        self.pkey = self.load_or_create_privatekey(self.config.client.private_key)
        if os.path.isfile(self.config.client.certificate):
            self.cert = self.load_certificate(self.config.client.certificate)
        else:
            self.cert = None

    def load_or_create_privatekey(self, pkey_file):
        """ Load a private key or create one """
        if os.path.isfile(pkey_file):
            with open(pkey_file, 'rb') as f:
                pkey = serialization.load_pem_private_key(
                    data=f.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            pkey = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            with open(pkey_file, 'wb') as f:
                f.write(pkey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        return pkey

    def load_certificate(self, cert_file):
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(
                data=f.read(),
                backend=default_backend()
            )
        return cert

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
        body = json.dumps({
            'csr': csr.public_bytes(serialization.Encoding.PEM).decode()
        })
        request = tornado.httpclient.HTTPRequest(
            url = self.config.client.server + '/authorize',
            method = "POST",
            body = body,
            headers = { 'Content-Type': 'application/json' },
            validate_cert = False)
        client = tornado.httpclient.HTTPClient()
        response = client.fetch(request)
        json_data = Munch.fromDict(json.loads(response.body.decode()))
        print(repr(json_data))
