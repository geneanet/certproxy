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

from .tools import load_certificate, get_cn, match_regexes

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
        elif not 'Content-Type' in self.request.headers:
            self.json_data = None
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

class GetCertHandler(JSONHandler):
    def __init__(self, application, request, server):
        super().__init__(application, request)
        self.server = server

    def get(self, domain):
        rawcert = self.request.get_ssl_certificate(binary_form=True)

        if rawcert:
            cert = load_certificate(cert_bytes=rawcert)
            host = get_cn(cert.subject)

            logger.debug('Certificate for %s requested by host %s.', domain, host)

            match = match_regexes(domain, self.server.config.server.certificates.keys())

            if match:
                certconfig = self.server.config.server.certificates[match.re.pattern]

                if host in certconfig.allowed_hosts:
                    logger.debug('Fetching certificate for domain %s', domain)
                    self.write({
                        'crt': '',
                        'key': ''
                    })
                else:
                    logger.warning('Host %s unauthorized for domain %s.', host, domain)
                    self.set_status(403)
            else:
                logger.warning('No config matching domain %s found.', domain)
                self.set_status(404)
        else:
            logger.warning('Certificate for %s requested by unauthentified host.', domain)
            self.set_status(401)

class ChallengeHandler(tornado.web.RequestHandler):
    def __init__(self, application, request, acmeproxy):
        super().__init__(application, request)
        self.acmeproxy = acmeproxy

    def get(self, token):
        keyauth = self.acmeproxy.get_challenge_keyauth(token)
        if keyauth:
            self.write(keyauth)
        else:
            self.set_status(404)

class Server:
    def __init__(self, config, acmeproxy):
        self.config = config # TODO : Check config keys
        self.acmeproxy = acmeproxy

    def run(self):
        # Start the app
        app = tornado.web.Application([
            (r"/authorize", AuthorizeHandler, dict(server=self)),
            (r"/cert/(?P<domain>[a-zA-Z0-9-_.]+)", GetCertHandler, dict(server=self)),
            (r"/.well-known/acme-challenge/(?P<token>.+)", ChallengeHandler, dict(acmeproxy=self.acmeproxy)),
        ])

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(self.config.server.ca.certificate, self.config.server.ca.private_key)
        context.load_verify_locations(cafile=self.config.server.ca.certificate)
        context.load_verify_locations(cafile=self.config.server.ca.crl)
        context.options &= ssl.OP_NO_SSLv3
        context.options &= ssl.OP_NO_SSLv2
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        context.verify_mode = ssl.CERT_OPTIONAL

        logger.info('Starting web server on port %d.', self.config.server.socket.port)
        server = tornado.httpserver.HTTPServer(app, ssl_options=context)
        server.listen(self.config.server.socket.port)
        tornado.ioloop.IOLoop.current().start()
