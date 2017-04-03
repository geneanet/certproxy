# -*- coding: utf-8 -*-
from gevent import monkey; monkey.patch_all()
import logging
import argparse
import yaml
from munch import Munch
from .server import Server, SSLServerAdapter
from .client import Client
from .tools import print_array
from .ca import CA
from .acmeproxy import ACMEProxy

rootlogger = logging.getLogger()
logger = logging.getLogger('certproxy')

logging.getLogger('acme.client').setLevel(logging.INFO)

def run():
    """ Run certproxy """
    # Parse CLI args
    parser = argparse.ArgumentParser()
    parser.add_argument('--logfile', nargs='?', default=None, help='Log file')
    parser.add_argument('--loglevel', nargs='?', default='info', help='Log level', choices = ['debug', 'info', 'warning', 'error', 'critical', 'fatal'])
    parser.add_argument('--logconfig', nargs='?', default=None, help='Logging configuration file (overrides --loglevel and --logfile)')
    parser.add_argument('--config', nargs='?', default='certproxy.yml', help='Config file')

    subp = parser.add_subparsers(dest='subcommand', title='Subcommands', help="Subcommand")
    subp.required = True
    parser_server = subp.add_parser('server', help='Start server')

    parser_auth = subp.add_parser('auth', help='Manage clients authorizations')
    subp_auth = parser_auth.add_subparsers(dest='action', title='Actions', help="Action")
    subp_auth.required = True
    subp_auth.add_parser('request', help='Request authorization from the server')
    subp_auth.add_parser('list', help='List pending authorization requests')
    parser_auth_sign = subp_auth.add_parser('accept', help='Accept a pending authorization request')
    parser_auth_sign.add_argument('host', help='Host to authorize')
    parser_auth_revoke = subp_auth.add_parser('revoke', help='Revoke an authorization')
    parser_auth_revoke.add_argument('host', help='Host to revoke')
    subp_auth.add_parser('clean', help='Clean revoked hosts certificates and unaccepted requests')

    parser_client = subp.add_parser('client', help='Act as a client to a CertProxy server')
    subp_client = parser_client.add_subparsers(dest='action', title='Actions', help="Action")
    subp_client.required = True
    parser_client_fetch = subp_client.add_parser('fetch', help='Fetch a certificate/key pair')
    parser_client_fetch.add_argument('domain', help='Domain')
    parser_client_fetch.add_argument('--force', default=False, action='store_true', help='Overwrite the local certificate if it is still valid')

    args = parser.parse_args()

    # Logging
    if args.logfile:
        logging.basicConfig(filename=args.logfile, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    else:
        logging.basicConfig(format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')

    loglevel = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL,
        'fatal': logging.FATAL
    }[args.loglevel]

    rootlogger.setLevel(loglevel)

    if args.logconfig:
        logging.config.fileConfig(args.logconfig)

    # Load config file
    try:
        with open(args.config, 'r') as f:
            config = Munch.fromDict(yaml.safe_load(f.read()))
    except Exception as e:
        logger.error('Unable to read config file (%s)' % e)
        exit(1)

    # Run requested subcommand
    if args.subcommand == 'server':
        acmeproxy = ACMEProxy(
            private_key_file=config.server.acme.private_key_file,
            directory_uri=config.server.acme.directory_uri,
            cache_path=config.server.acme.cache_path,
            email=config.server.acme.email,
            registration_file=config.server.acme.registration_file
        )
        server = Server(
            acmeproxy=acmeproxy,
            csr_path=config.server.ca.csr_path,
            crt_path=config.server.ca.crt_path,
            certificates_config=config.server.certificates,
            private_key_file=config.server.ca.private_key_file,
            certificate_file=config.server.ca.certificate_file,
            crl_file=config.server.ca.crl_file,
        )
        server.run(
            server=SSLServerAdapter,
            quiet=True,
            host=config.server.listen.host,
            port=config.server.listen.port,
        )
    elif args.subcommand == 'client':
        if args.action == 'fetch':
            client = Client(
                server=config.client.server,
                private_key_file=config.client.private_key_file,
                certificate_file=config.client.certificate_file,
                crt_path=config.client.crt_path,
                subject=config.client.subject,
            )
            client.requestcert(args.domain, force=args.force)
    elif args.subcommand == 'auth':
        caconfig = {
            'private_key_file': config.server.ca.private_key_file,
            'certificate_file': config.server.ca.certificate_file,
            'crl_file': config.server.ca.crl_file,
            'crt_path': config.server.ca.crt_path,
            'csr_path': config.server.ca.csr_path,
            'subject': config.server.ca.subject,
        }
        if args.action == 'list':
            ca = CA(**caconfig)
            hosts = ca.list_hosts()
            table = []
            headers = ['Host', 'Status', 'Key', 'Certificate']
            for host, hostinfos in hosts.items():
                table.append([host, hostinfos['status'], hostinfos['key_fingerprint'], hostinfos['cert_fingerprint']])
            print_array(table, headers)
        elif args.action == 'accept':
            ca = CA(**caconfig)
            ca.authorize_host(args.host)
        elif args.action == 'revoke':
            ca = CA(**caconfig)
            ca.revoke_host(args.host)
        elif args.action == 'request':
            client = Client(
                server=config.client.server,
                private_key_file=config.client.private_key_file,
                certificate_file=config.client.certificate_file,
                crt_path=config.client.crt_path,
                subject=config.client.subject,
            )
            client.requestauth()
        elif args.action == 'clean':
            ca = CA(**caconfig)
            ca.clean_hosts()
