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

def load_or_create_privatekey(pkey_file):
    """ Load a private key or create one """
    if os.path.isfile(pkey_file):
        with open(pkey_file, 'rb') as f:
            pkey = serialization.load_pem_private_key(
                data=f.read(),
                password=None,
                backend=default_backend()
            )
    else:
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

def load_certificate(cert_file):
    with open(cert_file, 'rb') as f:
        cert = x509.load_pem_x509_certificate(
            data=f.read(),
            backend=default_backend()
        )
    return cert

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
        uuid.uuid4().int # pylint: disable=E1101
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
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
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject.commonName),
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject.countryName),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.stateOrProvinceName),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organizationName),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizationalUnitName),
        ])
        crt = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            pkey.public_key()
        ).serial_number(
            uuid.uuid4().int # pylint: disable=E1101
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
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