# -*- coding: utf-8 -*-

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import os
import uuid
import datetime
from base64 import urlsafe_b64encode
import logging

logger = logging.getLogger('certproxy.tools.crypto')


def list_certificates(path):
    certs = []

    for crt_file in filter(lambda f: f.endswith('.crt') and not f.endswith('-chain.crt') ,os.listdir(path)):
        try:
            crt = load_certificate(os.path.join(path, crt_file))

            certs.append({
                'file': crt_file,
                'cn': get_cn(crt.subject),
                'not_valid_before': crt.not_valid_before,
                'not_valid_after': crt.not_valid_after,
                'fingerprint': x509_cert_fingerprint(crt),
                'key_fingerprint': rsa_key_fingerprint(crt.public_key()),
            })
        except Exception as e:
            logger.error('Error while loading certificate %s (%s)', crt_file, e)

    return certs


def dict_to_x509_name(data):
    name_attributes = []
    attr_name_oid = {
        'commonName': x509.NameOID.COMMON_NAME,
        'countryName': x509.NameOID.COUNTRY_NAME,
        'stateOrProvinceName': x509.NameOID.STATE_OR_PROVINCE_NAME,
        'locality': x509.NameOID.LOCALITY_NAME,
        'organizationName': x509.NameOID.ORGANIZATION_NAME,
        'organizationalUnitName': x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
    }
    for key, value in data.items():
        if not key in attr_name_oid:
            raise ValueError('{} is not a supported x509 name attribute'.format(key))
        name_attributes.append(x509.NameAttribute(attr_name_oid[key], value))
    return x509.Name(name_attributes)


def load_or_create_crl(crl_file, ca_crt, pkey):
    if os.path.isfile(crl_file):
        with open(crl_file, 'rb') as f:
            crl = x509.load_pem_x509_crl(
                data=f.read(),
                backend=default_backend()
            )
    else:
        crl = x509.CertificateRevocationListBuilder().issuer_name(
            ca_crt.subject
        ).last_update(
            datetime.datetime.utcnow()
        ).next_update(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).sign(
            private_key=pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        with open(crl_file, 'wb') as f:
            f.write(crl.public_bytes(
                encoding=serialization.Encoding.PEM,
            ))

    return crl


def update_crl(crl_file, revoked_certs, ca_crt, pkey):
    with open(crl_file, 'rb') as f:
        old_crl = x509.load_pem_x509_crl(
            data=f.read(),
            backend=default_backend()
        )

    crl = x509.CertificateRevocationListBuilder().issuer_name(
        ca_crt.subject
    ).last_update(
        datetime.datetime.utcnow()
    ).next_update(
        datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
    )

    for cert in revoked_certs:
        crl = crl.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(
                cert.serial
            ).revocation_date(
                datetime.datetime.utcnow()
            ).build(
                default_backend()
            )
        )

    for cert in old_crl:
        crl = crl.add_revoked_certificate(cert)

    crl = crl.sign(
        private_key=pkey,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    with open(crl_file, 'wb') as f:
        f.write(crl.public_bytes(  # pylint: disable=no-member
            encoding=serialization.Encoding.PEM,
        ))

    return crl


def revoked_cert(cert, crl):
    if cert.issuer != crl.issuer:
        raise Exception('The CRL has not been issued by the certificate issuer.')

    for revoked in crl:
        if cert.serial == revoked.serial_number:
            return revoked

    return None


def load_privatekey(pkey_file):
    """ Load a private key """
    with open(pkey_file, 'rb') as f:
        pkey = serialization.load_pem_private_key(
            data=f.read(),
            password=None,
            backend=default_backend()
        )
    return pkey


def create_privatekey(pkey_file):
    """ Create a private key """
    pkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    with open(pkey_file, 'wb') as f:
        f.write(pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return pkey


def load_or_create_privatekey(pkey_file):
    """ Load a private key or create one """
    if os.path.isfile(pkey_file):
        return load_privatekey(pkey_file)
    else:
        return create_privatekey(pkey_file)


def load_certificate(cert_file=None, cert_bytes=None):
    if cert_file:
        with open(cert_file, 'rb') as f:
            data = f.read()
    else:
        data = cert_bytes

    if '-----BEGIN'.encode() in data:
        cert = x509.load_pem_x509_certificate(
            data=data,
            backend=default_backend()
        )
    else:
        cert = x509.load_der_x509_certificate(
            data=data,
            backend=default_backend()
        )

    return cert


def get_cn(subject):
    return subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def sign_certificate_request(csr_file, crt_file, ca_crt, ca_pkey):
    with open(csr_file, 'rb') as f:
        csr = x509.load_pem_x509_csr(data=f.read(), backend=default_backend())

    crt = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_crt.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        uuid.uuid4().int  # pylint: disable=no-member
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
    ).add_extension(
        extension=x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=True,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False
        ),
        critical=True
    ).add_extension(
        extension=x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pkey.public_key()),
        critical=False
    ).sign(
        private_key=ca_pkey,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    with open(crt_file, 'wb') as f:
        f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))


def load_or_create_ca_certificate(crt_file, subject, pkey):
    """ Load a CA certificate or create a self-signed one """
    if os.path.isfile(crt_file):
        with open(crt_file, 'rb') as f:
            crt = x509.load_pem_x509_certificate(
                data=f.read(),
                backend=default_backend()
            )
    else:
        issuer = subject
        crt = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            pkey.public_key()
        ).serial_number(
            uuid.uuid4().int  # pylint: disable=no-member
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).add_extension(
            extension=x509.SubjectKeyIdentifier.from_public_key(pkey.public_key()),
            critical=True
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(pkey.public_key()),
            critical=True
        ).sign(
            private_key=pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(crt_file, 'wb') as f:
            f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))
    return crt


def rsa_key_fingerprint(key):
    """ Return the SHA256 fingerprint of an RSA public or private key in url safe BASE64 """
    fp = hashes.Hash(algorithm=hashes.SHA256(), backend=default_backend())

    if isinstance(key, rsa.RSAPrivateKey):
        fp.update(key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    elif isinstance(key, rsa.RSAPublicKey):
        fp.update(key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        ))

    return urlsafe_b64encode(fp.finalize()).decode()


def x509_cert_fingerprint(cert):
    return urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode()


def dump_pem(key_or_crt):
    if isinstance(key_or_crt, rsa.RSAPrivateKey):
        return key_or_crt.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(key_or_crt, rsa.RSAPublicKey):
        return key_or_crt.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
    else:
        return key_or_crt.public_bytes(
            encoding=serialization.Encoding.PEM
        )
