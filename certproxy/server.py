#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tornado.ioloop
import tornado.web
import tornado.httpserver
import os
import uuid
import ssl
from munch import Munch
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import logging

logger = logging.getLogger('certproxy.server')

class JSONHandler(tornado.web.RequestHandler):
    """Request handler for JSON requests."""
    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self.json_data = Munch()

    def prepare(self):
        if 'Content-Type' in self.request.headers and self.request.headers['Content-Type'] == 'application/json':
            if self.request.body:
                try:
                    self.json_data = Munch.fromDict(tornado.escape.json_decode(self.request.body))
                except ValueError as e:
                    logger.exception(e)
                    self.send_error(400) # Bad Request
        else:
            self.send_error(415) # Bad Media Type

class AuthorizeHandler(JSONHandler):
    def __init__(self, application, request, server):
        super().__init__(application, request)
        self.server = server

    def post(self):
        csr = x509.load_pem_x509_csr(data=self.json_data.csr.encode(), backend=default_backend())
        host = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        csr_file = os.path.join(self.server.config.server.ca.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.server.config.server.ca.crt_path, "%s.crt" % (host))

        if os.path.isfile(crt_file):
            # Return CRT
            with open(crt_file, 'r') as f:
                crt = f.read()
            self.write({
                'status': 'signed',
                'crt': crt
            })
        else:
            # Save CSR
            with open(csr_file, 'w') as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM).decode())
            self.set_status(202)
            self.write({
                'status': 'pending'
            })

class Server:
    def __init__(self, config):
        self.config = config # TODO : Check config keys

        self.pkey = self.load_or_create_privatekey(self.config.server.ca.private_key)
        self.cert = self.load_or_create_ca_certificate(self.config.server.ca.certificate, self.config.server.ca.subject)

    def list_hosts(self):
        csrlist = set([ os.path.splitext(csr)[0] for csr in os.listdir(self.config.server.ca.csr_path) ])
        crtlist = set([ os.path.splitext(crt)[0] for crt in os.listdir(self.config.server.ca.crt_path) ])

        return {
            'accepted': crtlist,
            'requested': csrlist - crtlist
        }

    def authorize_host(self, host):
        csr_file = os.path.join(self.config.server.ca.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.config.server.ca.crt_path, "%s.crt" % (host))

        self.sign_certificate_request(csr_file, crt_file)

    def sign_certificate_request(self, csr_file, crt_file):
        with open(csr_file, 'rb') as f:
            csr = x509.load_pem_x509_csr(data=f.read(), backend=default_backend())

        crt = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            uuid.uuid4().int # pylint: disable=E1101
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(self.pkey.public_key()),
            critical=False
        ).sign(
            private_key=self.pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(crt_file, 'wb') as f:
            f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))

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

    def load_or_create_ca_certificate(self, crt_file, subject):
        """ Load a CA certificate or create a self-signed one """
        if os.path.isfile(crt_file):
            with open(crt_file, 'rb') as f:
                crt = x509.load_pem_x509_certificate(
                    data=f.read(),
                    backend=default_backend()
                )
        else:
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject.commonName),
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject.countryName),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.stateOrProvinceName),
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organizationName),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizationalUnitName),
            ])
            crt = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.pkey.public_key()
            ).serial_number(
                uuid.uuid4().int # pylint: disable=E1101
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
            ).add_extension(
                extension=x509.KeyUsage(
                    digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=True,
                    data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
                ),
                critical=True
            ).add_extension(
                extension=x509.BasicConstraints(ca=True, path_length=0),
                critical=True
            ).add_extension(
                extension=x509.SubjectKeyIdentifier.from_public_key(self.pkey.public_key()),
                critical=True
            ).add_extension(
                extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(self.pkey.public_key()),
                critical=True
            ).sign(
                private_key=self.pkey,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            with open(crt_file, 'wb') as f:
                f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))
        return crt

    def run(self):
        # Start the app
        app = tornado.web.Application([
            (r"/authorize", AuthorizeHandler, dict(server=self)),
        ])

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(self.config.server.ca.certificate, self.config.server.ca.private_key)
        context.options &= ssl.OP_NO_SSLv3
        context.options &= ssl.OP_NO_SSLv2

        server = tornado.httpserver.HTTPServer(app, ssl_options=context)
        server.listen(8888)
        tornado.ioloop.IOLoop.current().start()
