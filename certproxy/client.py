#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tornado.httpclient
import os
import socket
import json
from munch import Munch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from .tools import load_certificate, load_or_create_privatekey, rsa_key_fingerprint

import logging

logger = logging.getLogger('certproxy.client')

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

        if json_data.status == 'pending':
            print("Authorization requested (key fingerprint: %s)." % rsa_key_fingerprint(self.pkey.public_key()))
        elif json_data.status == 'authorized':
            with open(self.config.client.certificate, 'w') as f:
                f.write(json_data.crt)
            print("Client authorized.")
