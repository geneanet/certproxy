# -*- coding: utf-8 -*-

import acme
import acme.client
import acme.challenges
import acme.messages
from OpenSSL import crypto
from datetime import datetime, timedelta
import logging
import os
from gevent.lock import Semaphore
from gevent import idle

from .tools import load_certificate, load_privatekey, load_or_create_privatekey, create_privatekey, dump_pem, readfile, writefile, list_certificates

logger = logging.getLogger('certproxy.acmeproxy')


class ChallengeKeyAuth:
    """ Retain Key Authentification data to answer an ACME challenge """

    def __init__(self, keyauth, expiration):
        """ Constructor """
        self.keyauth = keyauth
        self.expiration = expiration


class ACMEProxy:
    """ Proxy to request certificates from an ACME server with a local cache """

    def __init__(self, private_key_file, registration_file, directory_uri, cache_path, email=None):
        """ Constructor """
        self.registration_file = registration_file
        self.directory_uri = directory_uri
        self.cache_path = cache_path
        self.email = email

        pkey = load_or_create_privatekey(private_key_file)
        self.private_key = acme.jose.JWKRSA(key=pkey)

        # Dict to store domain renewal locks
        self.locks = {}

        # Dict to store the unanswered challenges
        self.challenges = {}

        # ACME Client will be instanciated lazily (not always needed)
        self.client = None

    def _init_client(self):
        if self.client is not None:
            return

        if os.path.isfile(self.registration_file):
            registration_uri = readfile(self.registration_file).strip()
        else:
            registration_uri = None

        # Instanciate an ACME client
        self.client = acme.client.Client(self.directory_uri, self.private_key)

        # If we are already registered
        if registration_uri:
            # Check registration
            logger.debug('Checking registration.')
            regr = acme.messages.RegistrationResource(body=acme.messages.Registration(), uri=registration_uri)
            regr = self.client.query_registration(regr)
        else:
            # Register
            logger.debug('Registering.')
            regr = self._register()
            # Save registration URI
            writefile(self.registration_file, regr.uri)

        logger.info('ACME registration verified.')

    def _register(self):
        """ Register a new account at the ACME server """
        self._init_client()
        newreg = acme.messages.NewRegistration(
            contact=['mailto:{}'.format(self.email)]
        )
        regr = self.client.register(newreg)
        return self.client.agree_to_tos(regr)

    def _supported_combination(self, challenges, combination):
        """ Check if a challenge combination is supported """
        return all([self._supported_challenge(challenges[challidx].chall) for challidx in combination])

    def _supported_challenge(self, challenge):
        """ Check if a challenge is supported """
        return isinstance(challenge, acme.challenges.HTTP01)

    def _answer_challenge(self, challb):
        """ Answer a challenge """
        self._init_client()
        # HTTP-01 challenge
        if isinstance(challb.chall, acme.challenges.HTTP01):
            response, validation = challb.response_and_validation(self.private_key)
            self._add_challenge_keyauth(challb.chall.encode('token'), validation)
            return self.client.answer_challenge(challb, response)
        # Unsupported challenge
        else:
            raise Exception("Unsupported challenge (type %s)" % (type(challb.chall)))

    def _process_auth(self, auth):
        """ Process an authorization request by answering the requested challenges """
        # Keep only combos with supported challenges
        supported_combos = [combo for combo in auth.body.combinations if self._supported_combination(auth.body.challenges, combo)]

        if not supported_combos:
            raise Exception("No challenges combination were supported.")

        # Pick the first supported combo and answer its challenges
        for challb in [auth.body.challenges[idx] for idx in supported_combos[0]]:
            self._answer_challenge(challb)

    def _gc_challenge_keyauth(self):
        """ Garbage collect expired challenges """
        for token, challenge in self.challenges.items():
            if challenge.expiration < datetime.utcnow():
                logger.debug("Deleting expired key authorization for token %s.", token)
                del self.challenges[token]

    def _add_challenge_keyauth(self, token, keyauth):
        """ Save challenge key authorization """
        logger.debug("Saving key authorization for token %s.", token)
        self.challenges[token] = ChallengeKeyAuth(
            keyauth=keyauth,
            expiration=datetime.utcnow() + timedelta(days=1)
        )

    def get_challenge_keyauth(self, token):
        """ Return challenge key authorization or None if not found """
        self._gc_challenge_keyauth()
        if token in self.challenges:
            return self.challenges[token].keyauth
        else:
            return None

    def clear_challenge_keyauth(self, token):
        """ Delete challenge key authorization """
        self._gc_challenge_keyauth()
        if token in self.challenges:
            logger.debug("Deleting key authorization for token %s.", token)
            del self.challenges[token]

    def _request_new_cert(self, domain, keyfile, altname=None):
        """ Generate a new certificate for a domain using an ACME authority """
        self._init_client()
        # Specific logger
        logger = logging.getLogger('certproxy.acmeproxy.acme')

        # Load the private key
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, readfile(keyfile, binary=True))

        # Create a CSR
        req = crypto.X509Req()
        req.get_subject().CN = domain
        req.add_extensions([
            crypto.X509Extension("keyUsage".encode(), False, "Digital Signature, Non Repudiation, Key Encipherment".encode()),
            crypto.X509Extension("basicConstraints".encode(), False, "CA:FALSE".encode()),
        ])
        if altname:
            req.add_extensions([
                crypto.X509Extension("subjectAltName".encode(), False, ', '.join(["DNS:{}".format(domain) for domain in altname]).encode())
            ])
        req.set_pubkey(key)
        req.sign(key, "sha256")

        # Validate every domain
        auths = []
        for dom in set(altname + [domain]):
            logger.debug("Requesting challenges for domain %s.", dom)
            auth = self.client.request_domain_challenges(dom)

            if auth.body.status != acme.messages.STATUS_VALID:
                logger.debug("Domain %s not yet authorized. Processing authorization.", dom)
                self._process_auth(auth)
            else:
                logger.debug("Domain %s already authorized, valid till %s.", dom, auth.body.expires)

            auths.append(auth)

        # Request certificate and chain
        logger.debug("Requesting certificate issuance for domain %s (altname: %s).", domain, ','.join(altname))
        (crt, auths) = self.client.poll_and_request_issuance(acme.jose.util.ComparableX509(req), auths)
        logger.debug("Requesting certificate chain for domain %s.", domain)
        chain = self.client.fetch_chain(crt)

        # Dump to PEM
        crt_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, crt.body)
        chain_pem = '\n'.join([crypto.dump_certificate(crypto.FILETYPE_PEM, link).decode() for link in chain]).encode()

        return (crt_pem, chain_pem)

    def get_cert(self, domain, altname=None, rekey=False, renew_margin=30, force_renew=False, auto_renew=True):
        """ Return a certificate from the local cache or request a new one if necessary """
        crtfile = os.path.join(self.cache_path, '{}.crt'.format(domain))
        chainfile = os.path.join(self.cache_path, '{}-chain.crt'.format(domain))
        keyfile = os.path.join(self.cache_path, '{}.key'.format(domain))

        # Acquire a lock to prevent that a domain has several renewal operations at the same time
        if not domain in self.locks:
            self.locks[domain] = Semaphore()

        self.locks[domain].acquire()

        try:
            # Try to load private key
            if os.path.isfile(keyfile):
                try:
                    key = load_privatekey(keyfile)
                except Exception:
                    logger.error('Unable to load private key %s', keyfile)
                    key = None
            else:
                key = None

            # Try to load certificate
            if os.path.isfile(crtfile):
                try:
                    crt = load_certificate(crtfile)
                except Exception:
                    logger.error('Unable to load certificate %s', crtfile)
                    crt = None
            else:
                crt = None

            # Try to load chain
            if os.path.isfile(chainfile):
                try:
                    chain = readfile(chainfile, binary=True)
                except Exception:
                    logger.error('Unable to load certificate chain %s', chainfile)
                    chain = bytes()
            else:
                chain = bytes()

            # If the key correspond to the certificate
            if crt and key and crt.public_key().public_numbers() == key.public_key().public_numbers():
                # If the certificate has expired
                if datetime.utcnow() > crt.not_valid_after:
                    logger.warning('The certificate for %s has expired', domain)

                # If forced renew OR auto renew during renew period
                if force_renew or (auto_renew and datetime.utcnow() > crt.not_valid_after - timedelta(days=renew_margin)):
                    logger.info('The certificate for %s will be renewed' + ' (forced renew)' if force_renew else '', domain)
                else:
                    # Return the cert and its key
                    logger.debug('Serving certificate from cache for %s', domain)
                    return (
                        dump_pem(key),
                        dump_pem(crt),
                        chain
                    )
            elif crt and key:
                logger.error('The key %s does not correspond to the certificate %s', keyfile, crtfile)

            # If no private key has been loaded or rekey is requested
            if not key or rekey:
                # generate a new key
                logger.debug('Generating a new key into %s', keyfile)
                key = create_privatekey(keyfile)

            # Request a new cert
            logger.debug('Requesting new certificate for %s from the CA', domain)
            (crt_pem, chain_pem) = self._request_new_cert(domain, keyfile, altname)
            key_pem = dump_pem(key)

            # Save to files
            writefile(keyfile, key_pem)
            writefile(crtfile, crt_pem)
            writefile(chainfile, chain_pem)

            # Return
            return (
                key_pem,
                crt_pem,
                chain_pem
            )

        finally:
            # Release the lock
            self.locks[domain].release()
            # Give the other threads the chance to acquire the lock
            idle()
            # Delete the lock if nobody else is using it
            if not self.locks[domain].locked():
                del self.locks[domain]

    def list_certificates(self):
        return list_certificates(self.cache_path)

    def delete_certificate(self, domain):
        certificate_file = os.path.join(self.cache_path, '{}.crt'.format(domain))
        chain_file = os.path.join(self.cache_path, '{}-chain.crt'.format(domain))
        key_file = os.path.join(self.cache_path, '{}.key'.format(domain))

        if os.path.isfile(certificate_file):
            logger.debug('Deleting %s', certificate_file)
            os.unlink(certificate_file)

        if os.path.isfile(chain_file):
            logger.debug('Deleting %s', chain_file)
            os.unlink(chain_file)

        if os.path.isfile(key_file):
            logger.debug('Deleting %s', key_file)
            os.unlink(key_file)

    def revoke_certificate(self, domain):
        self._init_client()
        certificate_file = os.path.join(self.cache_path, '{}.crt'.format(domain))
        cert = load_certificate(certificate_file)
        self.client.revoke(acme.jose.util.ComparableX509(cert), 0)
        self.delete_certificate(domain)
