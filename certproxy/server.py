#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from gevent import pywsgi
from bottle import Bottle, request, response, ServerAdapter
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

class SSLServerAdapter(ServerAdapter):
    def run(self, handler):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(handler.config.server.ca.certificate, handler.config.server.ca.private_key)
        context.load_verify_locations(cafile=handler.config.server.ca.certificate)
        context.load_verify_locations(cafile=handler.config.server.ca.crl)
        context.options &= ssl.OP_NO_SSLv3
        context.options &= ssl.OP_NO_SSLv2
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        context.verify_mode = ssl.CERT_OPTIONAL
        self.options['ssl_context'] = context

        server = pywsgi.WSGIServer(
            (self.host, self.port),
            handler,
            ssl_context=context,
            handler_class=RequestHandler,
            log=logger,
            error_log=logger,
        )
        server.serve_forever()

class RequestHandler(pywsgi.WSGIHandler):
    def get_environ(self):
        env = super(RequestHandler, self).get_environ()
        env['ssl_certificate'] = self.socket.getpeercert(binary_form=True)
        return env

class Server(Bottle):
    def __init__(self, config, acmeproxy):
        super(Server, self).__init__()
        self.config = config
        self.acmeproxy = acmeproxy

        self.route('/authorize', callback=self.HandleAuth)
        self.route('/cert/<domain>', callback=self.HandleCert)
        self.route('/.well-known/acme-challenge/<token>', callback=self.HandleChallenge)

    def HandleAuth(self):
        request_data = Munch(request.json)

        csr = x509.load_pem_x509_csr(data=request_data.csr.encode(), backend=default_backend())
        host = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        csr_file = os.path.join(self.config.server.ca.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.config.server.ca.crt_path, "%s.crt" % (host))

        if os.path.isfile(crt_file):
            # Return CRT
            with open(crt_file, 'r') as f:
                crt = f.read()
            return {
                'status': 'authorized',
                'crt': crt
            }
        else:
            # Save CSR
            with open(csr_file, 'w') as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM).decode())
            response.status = 202
            return {
                'status': 'pending'
            }

    def HandleCert(self, domain):
        rawcert = request.environ['ssl_certificate']

        if rawcert:
            cert = load_certificate(cert_bytes=rawcert)
            host = get_cn(cert.subject)

            logger.debug('Certificate for %s requested by host %s.', domain, host)

            match = match_regexes(domain, self.config.server.certificates.keys())

            if match:
                certconfig = self.config.server.certificates[match.re.pattern]

                if host in certconfig.allowed_hosts:
                    logger.debug('Fetching certificate for domain %s', domain)
                    altname = [match.expand(name) for name in certconfig.altname]
                    (key, crt, chain) = self.acmeproxy.get_cert(
                        domain,
                        altname,
                        certconfig.rekey if 'rekey' in certconfig else False,
                        certconfig.renew_margin if 'renew_margin' in certconfig else 30,
                    )
                    return {
                        'crt': crt.decode(),
                        'key': key.decode(),
                        'chain': chain.decode()
                    }
                else:
                    logger.warning('Host %s unauthorized for domain %s.', host, domain)
                    response.status = 403
            else:
                logger.warning('No config matching domain %s found.', domain)
                response.status = 404
        else:
            logger.warning('Certificate for %s requested by unauthentified host.', domain)
            response.status = 401

    def HandleChallenge(self, token):
        keyauth = self.acmeproxy.get_challenge_keyauth(token)
        if keyauth:
            return keyauth
        else:
            response.status = 404
