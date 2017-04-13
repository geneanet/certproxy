# -*- coding: utf-8 -*-

from gevent import pywsgi
from bottle import Bottle, request, response, ServerAdapter, HTTPResponse
import os
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .tools.crypto import load_certificate
from .tools.json import dumps

import logging

logger = logging.getLogger('certproxy.server')


class SSLServerAdapter(ServerAdapter):

    def run(self, handler):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(handler.certificate_file, handler.private_key_file)
        context.load_verify_locations(cafile=handler.certificate_file)
        context.load_verify_locations(cafile=handler.crl_file)
        context.options &= ssl.OP_NO_SSLv3
        context.options &= ssl.OP_NO_SSLv2
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        context.verify_mode = ssl.CERT_OPTIONAL
        self.options['ssl_context'] = context

        logger.info('Starting server on host %s port %d.', self.host, self.port)

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


class JSONPlugin(object):

    def setup(self, app):
        def default_error_handler(res):
            if res.content_type == "application/json":
                return res.body
            res.content_type = "application/json"
            return dumps({'message': str(res.exception if res.exception else res.body)})

        app.default_error_handler = default_error_handler

    def apply(self, callback, route):
        def wrapper(*a, **ka):
            try:
                rv = callback(*a, **ka)
            except HTTPResponse as resp:
                rv = resp

            if isinstance(rv, dict):
                json_response = dumps(rv)
                response.content_type = 'application/json'
                return json_response
            elif isinstance(rv, HTTPResponse) and isinstance(rv.body, dict):
                rv.body = dumps(rv.body)
                rv.content_type = 'application/json'
            return rv

        return wrapper


class Server(Bottle):

    def __init__(self, acmeproxy, csr_path, crt_path, certificates_config, private_key_file, certificate_file, crl_file, admin_hosts):
        super(Server, self).__init__()
        self.acmeproxy = acmeproxy
        self.csr_path = csr_path
        self.crt_path = crt_path
        self.certificates_config = certificates_config
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.crl_file = crl_file
        self.admin_hosts = admin_hosts

        self.route('/authorize', callback=self.HandleAuth, method='POST')
        self.route('/cert', callback=self.HandleListCerts)
        self.route('/cert/*/renew', callback=self.HandleRenewAll, method='POST')
        self.route('/cert/<domain>', callback=self.HandleCert)
        self.route('/cert/<domain>/renew', callback=self.HandleCert, method='POST')
        self.route('/cert/<domain>/revoke', callback=self.HandleRevokeCert, method='POST')
        self.route('/cert/<domain>/delete', callback=self.HandleDeleteCert, method='POST')
        self.route('/.well-known/acme-challenge/<token>', callback=self.HandleChallenge)
        self.route('/healthcheck', callback=self.HandleHealthCheck)

        self.install(JSONPlugin())

    def _get_cert_config_if_allowed(self, domain, cert):
        if cert is not None:
            if isinstance(cert, bytes):
                cert = load_certificate(cert_bytes=cert)

            if isinstance(cert, x509.Certificate):
                host = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            else:
                raise TypeError('cert must be a raw certificate in PEM or DER format or an x509.Certificate instance.')

        else:
            logger.warning('Request received for domain %s by unauthentified host.', domain)
            raise HTTPResponse(
                status=401,
                body={'message': 'Authentication required'}
            )

        certconfig = self.certificates_config.match(domain)

        if certconfig:
            logger.debug('Domain %s matches pattern %s', domain, certconfig.pattern)
            if host in self.admin_hosts or host in certconfig.allowed_hosts:
                return certconfig
            else:
                logger.warning('Host %s unauthorized for domain %s.', host, domain)
                raise HTTPResponse(
                    status=403,
                    body={'message': 'Host {} unauthorized for domain {}'.format(host, domain)}
                )
        else:
            logger.warning('No config matching domain %s found.', domain)
            raise HTTPResponse(
                status=404,
                body={'message': 'No configuration found for domain {}'.format(domain)}
            )

    def _assert_admin(self, cert):
        if cert is not None:
            if isinstance(cert, bytes):
                cert = load_certificate(cert_bytes=cert)

            if isinstance(cert, x509.Certificate):
                host = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            else:
                raise TypeError('cert must be a raw certificate in PEM or DER format or an x509.Certificate instance.')

        else:
            logger.warning('Admin command received by unauthentified host.')
            raise HTTPResponse(
                status=401,
                body={'message': 'Authentication required'}
            )

        if host not in self.admin_hosts:
            logger.warning('Host %s unauthorized for admin commands.', host)
            raise HTTPResponse(
                status=403,
                body={'message': 'Host {} unauthorized for admin commands'.format(host)}
            )

    def HandleAuth(self):
        request_data = request.json

        csr = x509.load_pem_x509_csr(data=request_data['csr'].encode(), backend=default_backend())  # pylint: disable=unsubscriptable-object
        host = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        csr_file = os.path.join(self.csr_path, "%s.csr" % (host))
        crt_file = os.path.join(self.crt_path, "%s.crt" % (host))

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

        certconfig = self._get_cert_config_if_allowed(domain, rawcert)

        logger.debug('Fetching certificate for domain %s', domain)

        (key, crt, chain) = self.acmeproxy.get_cert(
            domain=domain,
            altname=certconfig.altname,
            rekey=certconfig.rekey,
            renew_margin=certconfig.renew_margin,
            force_renew=('force_renew' in request.query and request.query['force_renew'] == 'true'),  # pylint: disable=unsupported-membership-test,unsubscriptable-object
            auto_renew=certconfig.renew_on_fetch
        )

        return {
            'crt': crt.decode(),
            'key': key.decode(),
            'chain': chain.decode()
        }

    def HandleListCerts(self):
        rawcert = request.environ['ssl_certificate']

        self._assert_admin(rawcert)

        certs = self.acmeproxy.list_certificates()

        return {
            'certificates': certs
        }

    def HandleRenewAll(self):
        rawcert = request.environ['ssl_certificate']

        self._assert_admin(rawcert)

        result = {
            'ok': [],
            'error': []
        }

        for cert in self.acmeproxy.list_certificates():
            domain = cert['cn']
            certconfig = self.certificates_config.match(domain)
            if certconfig:
                logger.debug('Getting certificate for domain %s', domain)
                try:
                    self.acmeproxy.get_cert(
                        domain=domain,
                        altname=certconfig.altname,
                        rekey=certconfig.rekey,
                        renew_margin=certconfig.renew_margin,
                        force_renew=('force_renew' in request.query and request.query['force_renew'] == 'true'),  # pylint: disable=unsupported-membership-test,unsubscriptable-object
                    )
                    result['ok'].append(domain)
                except Exception as e:
                    logger.error('Encountered exception while getting certificate for domain %s (%s)', domain, e)
                    result['error'].append(domain)
            else:
                logger.error('No configuration found for domain %s', domain)
                result['error'].append(domain)

        return result

    def HandleRevokeCert(self, domain):
        rawcert = request.environ['ssl_certificate']

        self._assert_admin(rawcert)

        self.acmeproxy.revoke_certificate(domain)

        return {
            'status': 'revoked'
        }

    def HandleDeleteCert(self, domain):
        rawcert = request.environ['ssl_certificate']

        self._assert_admin(rawcert)

        self.acmeproxy.delete_certificate(domain)

        return {
            'status': 'deleted'
        }

    def HandleChallenge(self, token):
        keyauth = self.acmeproxy.get_challenge_keyauth(token)
        if keyauth:
            return keyauth
        else:
            response.status = 404

    def HandleHealthCheck(self):
        response.status = 200
        return {
            'status': 'alive'
        }
