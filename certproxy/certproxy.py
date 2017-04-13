# -*- coding: utf-8 -*-

from gevent import monkey
monkey.patch_all()
import logging
import argparse
import yaml
import os.path
from .tools.misc import print_array
from .ca import CA
from .config import Config

rootlogger = logging.getLogger()
logger = logging.getLogger('certproxy')

logging.getLogger('acme.client').setLevel(logging.INFO)


def run():
    """ Run certproxy """
    # Parse CLI args
    parser = argparse.ArgumentParser()
    parser.add_argument('--logfile', nargs='?', default=None, help='Log file')
    parser.add_argument('--loglevel', nargs='?', default='info', help='Log level', choices=['debug', 'info', 'warning', 'error', 'critical', 'fatal'])
    parser.add_argument('--logconfig', nargs='?', default=None, help='Logging configuration file (overrides --loglevel and --logfile)')
    parser.add_argument('--config', nargs='?', default=None, help='Config file')

    subp = parser.add_subparsers(dest='subcommand', title='Subcommands', help="Subcommand")
    subp.required = True
    parser_server = subp.add_parser('server', help='Start server')

    parser_auth = subp.add_parser('auth', help='Manage clients authorizations')
    subp_auth = parser_auth.add_subparsers(dest='action', title='Actions', help="Action")
    subp_auth.required = True
    subp_auth.add_parser('list', help='List pending authorization requests')
    parser_auth_sign = subp_auth.add_parser('accept', help='Accept a pending authorization request')
    parser_auth_sign.add_argument('host', help='Host to authorize')
    parser_auth_revoke = subp_auth.add_parser('revoke', help='Revoke an authorization')
    parser_auth_revoke.add_argument('host', help='Host to revoke')
    subp_auth.add_parser('clean', help='Clean revoked hosts certificates and unaccepted requests')

    parser_admin = subp.add_parser('admin', help='Act as an admin of a CertProxy server')
    subp_admin = parser_admin.add_subparsers(dest='action', title='Actions', help="Action")
    subp_admin.required = True
    subp_admin.add_parser('list', help='List managed certificates')
    parser_admin_delete = subp_admin.add_parser('delete', help='Delete a managed certificate')
    parser_admin_delete.add_argument('domain', help='Domain')
    parser_admin_revoke = subp_admin.add_parser('revoke', help='Revoke a managed certificate')
    parser_admin_revoke.add_argument('domain', help='Domain')
    parser_admin_renew = subp_admin.add_parser('renew', help='Renew managed certificate')
    parser_admin_renew.add_argument('domain', help='Domain')
    parser_admin_renew.add_argument('--force', default=False, action='store_true', help='Force the renewal of the certificates')
    parser_admin_renewall = subp_admin.add_parser('renew-all', help='Renew all managed certificates')
    parser_admin_renewall.add_argument('--force', default=False, action='store_true', help='Force the renewal of the certificates')

    parser_client = subp.add_parser('client', help='Act as a client to a CertProxy server')
    subp_client = parser_client.add_subparsers(dest='action', title='Actions', help="Action")
    subp_client.required = True
    subp_client.add_parser('requestauth', help='Request authorization from the server')
    subp_client.add_parser('list', help='List local certificates')
    parser_client_fetch = subp_client.add_parser('fetch', help='Fetch a certificate/key pair')
    parser_client_fetch.add_argument('domain', help='Domain')
    parser_client_fetch.add_argument('--force', default=False, action='store_true', help='Overwrite the local certificate if it is still valid')
    parser_client_fetch.add_argument('--force-renew', default=False, action='store_true', help='Force the renewal of the certificate')
    parser_client_fetchall = subp_client.add_parser('fetchall', help='Fetch again all local certificates')
    parser_client_fetchall.add_argument('--force', default=False, action='store_true', help='Overwrite the local certificates if they are still valid')
    parser_client_fetchall.add_argument('--force-renew', default=False, action='store_true', help='Force the renewal of the certificates')
    parser_client_delete = subp_client.add_parser('delete', help='Delete a local certificate')
    parser_client_delete.add_argument('domain', help='Domain')

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
        if args.config:
            configfile = args.config
        elif os.path.isfile('certproxy.yml'):
            configfile = 'certproxy.yml'
        elif os.path.isfile('/etc/certproxy/certproxy.yml'):
            configfile = '/etc/certproxy/certproxy.yml'
        else:
            configfile = '/etc/certproxy.yml'

        with open(configfile, 'r') as f:
            config = Config(yaml.safe_load(f.read()))
    except Exception as e:
        logger.error('Unable to read config file %s (%s)', configfile, e)
        exit(1)

    # Run requested subcommand
    if args.subcommand == 'server':
        from .acmeproxy import ACMEProxy
        from .server import Server, SSLServerAdapter
        acmeproxy = ACMEProxy(
            private_key_file=config.server.acme.private_key_file,
            directory_uri=config.server.acme.directory_uri,
            cache_path=config.server.acme.cache_path,
            email=config.server.acme.email,
            registration_file=config.server.acme.registration_file
        )
        # Instanciate CA to make sure CA private key/certificate are OK
        ca = CA(
            private_key_file=config.server.ca.private_key_file,
            certificate_file=config.server.ca.certificate_file,
            crl_file=config.server.ca.crl_file,
            crt_path=config.server.ca.crt_path,
            csr_path=config.server.ca.csr_path,
            subject=config.server.ca.subject,
        )
        server = Server(
            acmeproxy=acmeproxy,
            csr_path=config.server.ca.csr_path,
            crt_path=config.server.ca.crt_path,
            certificates_config=config.server.certificates_config,
            private_key_file=config.server.ca.private_key_file,
            certificate_file=config.server.ca.certificate_file,
            crl_file=config.server.ca.crl_file,
            admin_hosts=config.server.admin_hosts,
        )
        server.run(
            server=SSLServerAdapter,
            quiet=True,
            host=config.server.listen.host,
            port=config.server.listen.port,
        )
    elif args.subcommand == 'admin':
        from .client import Client
        client = Client(
        server=config.client.server,
        private_key_file=config.client.private_key_file,
        certificate_file=config.client.certificate_file,
        crt_path=config.client.crt_path,
        subject=config.client.subject,
        certificates_config=config.client.certificates_config
        )
        if args.action == 'list':
            table = []
            headers = ['CN', 'Expiration', 'Fingerprint']
            for cert in client.admin_list():
                table.append([
                    cert['cn'],
                    cert['not_valid_after'],
                    cert['fingerprint'],
                ])
            print_array(table, headers)
        elif args.action == 'delete':
            client.admin_delete(args.domain)
        elif args.action == 'revoke':
            client.admin_revoke(args.domain)
        elif args.action == 'renew':
            client.admin_renew(args.domain, args.force)
        elif args.action == 'renew-all':
            client.admin_renewall(args.force)
    elif args.subcommand == 'client':
        from .client import Client
        client = Client(
            server=config.client.server,
            private_key_file=config.client.private_key_file,
            certificate_file=config.client.certificate_file,
            crt_path=config.client.crt_path,
            subject=config.client.subject,
            certificates_config=config.client.certificates_config
        )
        if args.action == 'fetch':
            client.requestcert(args.domain, force=args.force, force_renew=args.force_renew)
        elif args.action == 'requestauth':
            client.requestauth()
        elif args.action == 'list':
            table = []
            headers = ['CN', 'Expiration', 'Fingerprint']
            for cert in client.list_certificates():
                table.append([
                    cert['cn'],
                    cert['not_valid_after'],
                    cert['fingerprint'],
                ])
            print_array(table, headers)
        elif args.action == 'fetchall':
            for cert in client.list_certificates():
                client.requestcert(cert['cn'], force=args.force, force_renew=args.force_renew)
        elif args.action == 'delete':
            client.delete_certificate(args.domain)
    elif args.subcommand == 'auth':
        ca = CA(
            private_key_file=config.server.ca.private_key_file,
            certificate_file=config.server.ca.certificate_file,
            crl_file=config.server.ca.crl_file,
            crt_path=config.server.ca.crt_path,
            csr_path=config.server.ca.csr_path,
            subject=config.server.ca.subject,
        )
        if args.action == 'list':
            hosts = ca.list_hosts()
            table = []
            headers = ['Host', 'Status', 'Key', 'Certificate']
            for host, hostinfos in hosts.items():
                table.append([host, hostinfos['status'], hostinfos['key_fingerprint'], hostinfos['cert_fingerprint']])
            print_array(table, headers)
        elif args.action == 'accept':
            ca.authorize_host(args.host)
        elif args.action == 'revoke':
            ca.revoke_host(args.host)
        elif args.action == 'clean':
            ca.clean_hosts()
