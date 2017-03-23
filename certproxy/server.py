#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tornado.ioloop
import tornado.web
import tornado.httpserver
import os
import ssl
from munch import Munch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .tools import load_or_create_privatekey, sign_certificate_request, load_or_create_ca_certificate, rsa_key_fingerprint

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
                'status': 'authorized',
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

        self.pkey = load_or_create_privatekey(self.config.server.ca.private_key)
        self.cert = load_or_create_ca_certificate(self.config.server.ca.certificate, self.config.server.ca.subject, self.pkey)

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

        sign_certificate_request(csr_file, crt_file, self.cert, self.pkey)

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
