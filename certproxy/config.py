# -*- coding: utf-8 -*-

import re
from .tools import dict_to_x509_name
import textwrap

def check_config(config, types):
    if not isinstance(config, dict):
        raise TypeError('config must be a dict')

    for key, (valuetype, mandatory) in types.items():
        if mandatory and (key not in config or config[key] is None):
            raise TypeError('{} must be defined'.format(key))
        elif key in config and not isinstance(config[key], valuetype):
            raise TypeError('{} must be of type {}'.format(key, valuetype.__name__))

class AbstractConfig:

    def __repr__(self):
        ret = ''
        for key, value in self.__dict__.items():
            ret += key + ':\n'
            if value.__class__ == list:
                for item in value:
                    ret += textwrap.indent('- ' + repr(item), '      ')[2:] + '\n'
            else:
                ret += textwrap.indent(repr(value), '    ') + '\n'
        return ret


class FileProperties(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'path': (str, True),
            'owner': (str, False),
            'group': (str, False),
            'mode': (int, False)
        })

        self.path = config['path']
        self.owner = config['owner'] if 'owner' in config else None
        self.group = config['group'] if 'group' in config else None
        self.mode = config['mode'] if 'mode' in config else None


class CertClientConfig(AbstractConfig):

    def __init__(self, pattern, config):
        check_config(config, types={
            'execute': (str, False),
            'deploy_crt': (dict, False),
            'deploy_key': (dict, False),
            'deploy_chain': (dict, False),
            'priority': (int, False),
        })

        try:
            re.compile(pattern)
        except:
            raise ValueError('pattern must be a python compatible regular expression')

        self.pattern = pattern
        self.execute = config['execute'] if 'execute' in config else None
        self.deploy_key = FileProperties(config['deploy_key']) if 'deploy_key' in config else None
        self.deploy_crt = FileProperties(config['deploy_crt']) if 'deploy_crt' in config else None
        self.deploy_chain = FileProperties(config['deploy_chain']) if 'deploy_chain' in config else None
        self.priority = config['priority'] if 'priority' in config else 0


class CertServerConfig(AbstractConfig):

    def __init__(self, pattern, config):
        check_config(config, types={
            'altname': (list, False),
            'allowed_hosts': (list, False),
            'rekey': (bool, False),
            'renew_margin': (int, False),
            'priority': (int, False),
        })

        try:
            re.compile(pattern)
        except:
            raise ValueError('pattern must be a python compatible regular expression')

        self.pattern = pattern
        self.priority = config['priority'] if 'priority' in config else 0
        self.rekey = config['rekey'] if 'rekey' in config else False
        self.renew_margin = config['renew_margin'] if 'renew_margin' in config else 30

        if 'altname' in config:
            for name in config['altname']:
                if not isinstance(name, str):
                    raise TypeError('AltName {} is not a string'.format(name))
            self.altname = config['altname']
        else:
            self.altname = []

        if 'allowed_hosts' in config:
            for host in config['allowed_hosts']:
                if not isinstance(host, str):
                    raise TypeError('host {} is not a string'.format(host))
            self.allowed_hosts = config['allowed_hosts']
        else:
            self.allowed_hosts = []


class ListenConfig(AbstractConfig):

    def __init__(self, config=None):
        if config is None:
            config = {}

        check_config(config, types={
            'host': (str, False),
            'port': (int, False),
        })

        self.host = config['host'] if 'host' in config else '0.0.0.0'
        self.port = config['port'] if 'port' in config else 7840


class CAConfig(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'private_key_file': (str, True),
            'certificate_file': (str, True),
            'crt_path': (str, True),
            'csr_path': (str, True),
            'crl_file': (str, True),
            'subject': (dict, False),
        })

        self.private_key_file = config['private_key_file']
        self.certificate_file = config['certificate_file']
        self.crt_path = config['crt_path']
        self.csr_path = config['csr_path']
        self.crl_file = config['crl_file']
        self.subject = dict_to_x509_name(config['subject']) if 'subject' in config else dict_to_x509_name({'commonName': 'CertProxy CA'})


class ACMEConfig(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'private_key_file': (str, True),
            'directory_uri': (str, True),
            'registration_file': (str, True),
            'email': (str, True),
            'cache_path': (str, True),
        })

        self.private_key_file = config['private_key_file']
        self.directory_uri = config['directory_uri']
        self.registration_file = config['registration_file']
        self.email = config['email']
        self.cache_path = config['cache_path']


class ClientConfig(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'server': (str, True),
            'private_key_file': (str, True),
            'certificate_file': (str, True),
            'crt_path': (str, True),
            'subject': (dict, False),
            'certificates': (dict, False),
        })

        self.server = config['server']
        self.private_key_file = config['private_key_file']
        self.certificate_file = config['certificate_file']
        self.crt_path = config['crt_path']
        self.subject = dict_to_x509_name(config['subject']) if 'subject' in config else dict_to_x509_name({})

        self.certificates_config = []
        if 'certificates' in config:
            for pattern, certificate_config in config['certificates'].items():
                self.certificates_config.append(CertClientConfig(pattern, certificate_config))
        self.certificates_config.sort(key=lambda c: c.priority, reverse=True)


class ServerConfig(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'listen': (dict, False),
            'ca': (dict, True),
            'acme': (dict, True),
            'certificates': (dict, True),
        })

        self.listen = ListenConfig(config['listen']) if 'listen' in config else ListenConfig()
        self.ca = CAConfig(config['ca'])
        self.acme = ACMEConfig(config['acme'])

        self.certificates_config = []
        for pattern, certificate_config in config['certificates'].items():
            self.certificates_config.append(CertServerConfig(pattern, certificate_config))
        self.certificates_config.sort(key=lambda c: c.priority, reverse=True)


class Config(AbstractConfig):

    def __init__(self, config):
        check_config(config, types={
            'server': (dict, False),
            'client': (dict, False),
        })

        self.server = ServerConfig(config['server']) if 'server' in config else None
        self.client = ClientConfig(config['client']) if 'client' in config else None

        if not (self.client or self.server):
            raise TypeError('At least a client or a server configuration must be available')