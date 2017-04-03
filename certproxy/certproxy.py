# -*- coding: utf-8 -*-
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

    parser_cert = subp.add_parser('cert', help='Ask server for certificates')
    subp_cert = parser_cert.add_subparsers(dest='action', title='Actions', help="Action")
    subp_cert.required = True
    parser_cert_fetch = subp_cert.add_parser('fetch', help='Fetch a key/certificate pair')
    parser_cert_fetch.add_argument('domain', help='Domain')

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
        server = Server(config, acmeproxy)
        server.run(server=SSLServerAdapter)
    elif args.subcommand == 'cert':
        if args.action == 'fetch':
            client = Client(config)
            client.requestcert(args.domain)
    elif args.subcommand == 'auth':
        if args.action == 'list':
            ca = CA(config)
            hosts = ca.list_hosts()
            table = []
            headers = ['Host', 'Status', 'Key', 'Certificate']
            for host, hostinfos in hosts.items():
                table.append([host, hostinfos['status'], hostinfos['key_fingerprint'], hostinfos['cert_fingerprint']])
            print_array(table, headers)
        elif args.action == 'accept':
            ca = CA(config)
            ca.authorize_host(args.host)
        elif args.action == 'revoke':
            ca = CA(config)
            ca.revoke_host(args.host)
        elif args.action == 'request':
            client = Client(config)
            client.requestauth()
        elif args.action == 'clean':
            ca = CA(config)
            ca.clean_hosts()
