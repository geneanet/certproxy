# -*- coding: utf-8 -*-
import logging
import argparse
import yaml
from munch import Munch
from .server import Server
from .client import Client
from .tools import print_array

rootlogger = logging.getLogger()
logger = logging.getLogger('certproxy')

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
        server = Server(config)
        server.run()
    elif args.subcommand == 'auth':
        if args.action == 'list':
            server = Server(config)
            hosts = server.list_hosts()
            table = []
            headers = ['Host', 'Status', 'Key', 'Certificate']
            for host, hostinfos in hosts.items():
                table.append([host, hostinfos['status'], hostinfos['key_fingerprint'], hostinfos['cert_fingerprint']])
            print_array(table, headers)
        elif args.action == 'accept':
            server = Server(config)
            server.authorize_host(args.host)
        elif args.action == 'revoke':
            pass
        elif args.action == 'request':
            client = Client(config)
            client.requestauth()
