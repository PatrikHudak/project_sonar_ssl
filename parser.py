#!/usr/bin/env python

"""
parser.py
~~~~~~~~~

Parse Base64 encoded DER X509v3 certificate into dict
"""

from __future__ import print_function

import binascii
import textwrap

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def pem_format_certificate(cert):
    """
    Make base64 encoded cert "PEM compliant" -- enclose between 'BEGIN/END certificate'
    strings and wrap lines to 64 chars

    :param cert: Base64 encoded certificate as provided in Sonar's SSL data
    :return: String which is "PEM formatted"
    """

    bounded = '\n'.join(textwrap.wrap(cert, 64))
    return '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----'.format(bounded)

def get_cert_fingeprint(cert, hash_algo):
    """
    Get certificate fingerprint as hex digest

    :param cert: parsed certificate from cryptography package
    :param hash_algo: object for certificate fingerprint from cryptography package
    :return: fingerprint of certificate (with given hashing function) as hex digest without ':' between bytes
    """

    return binascii.hexlify(cert.fingerprint(hash_algo))

def parse_subject(subject):
    """
    Transform subject such as Issuer to dictionary from list of objects

    :param subject: Subject object from cryptography package
    :return: parsed dictionary with name identifiers which represent DN
    """

    dn = {}
    for identifier in subject:
        key = identifier.oid._name
        if not key:
            continue
        dn[key] = identifier.value
    return dn


def get_subject_alt_names(cert):
    """
    Gets list of subject alternative name from certificate extensions

    :param cert: Parsed certificate as dictionary
    :return: list of name tuples (see SubjectAltName object) representing SANs
    """

    values = cert.get('extensions', {}).get('subjectAltName')
    if not values:
        return []
    sans = []

    for value in values.split(','):
        value = value.strip()
        if not value:
            continue
        if value.startswith('DNS:'):
            # DNS subject
            value = value.lstrip('DNS:').strip()
            sans.append(SubjectAltName(type='dns', value=value, wildcard=is_wildcard(value)))
        elif value.startswith('IP Address:'):
            # IP address subject
            value = value.lstrip('IP Address:').strip()
            sans.append(SubjectAltName(type='ip', value=value, wildcard=is_wildcard(value)))
    return sans

def parse_extensions(extensions):
    """
    Transfort certificate extensions to simpler dictionary

    :param extensions: Extensions object from cryptography package
    :return: dictionary with transformed extension fields
    """

    # TODO: Authority Information Access
    # TODO: CRL Distribution Points
    # TODO: Policy Mappings
    # TODO: Issuer Alternative Name
    # TODO: Subject Directory Attributes
    # TODO: Name Constraints
    # TODO: Policy Constraints
    # TODO: Inhibit anyPolicy
    # TODO: Subject Information Access
    # TODO: More SAN values

    transformed_extensions = {}
    for extension in extensions:
        identifier = extension.oid._name

        if identifier == 'basicConstraints':
            # The basic constraints extension identifies whether the subject of the
            # certificate is a CA and the maximum depth of valid certification
            # paths that include this certificate.

            fields = {
                'ca': extension.value.ca
            }
        elif identifier == 'keyUsage':
            # The key usage extension defines the purpose (e.g., encipherment, signature, certificate signing)
            # of the key contained in the certificate.

            fields = {
                'digitalSignature': extension.value.digital_signature or False,
                'contentCommitment': extension.value.content_commitment or False,
                'keyEncipherment': extension.value.key_encipherment or False,
                'dataEncipherment': extension.value.data_encipherment or False,
                'keyAgreement': extension.value.key_agreement or False,
                'keyCertSign': extension.value.key_cert_sign or False,
                'crlSign': extension.value.crl_sign or False
            }
            if fields['keyAgreement']:
                fields.update({
                    'encipherOnly': extension.value.encipher_only,
                    'decipherOnly': extension.value.decipher_only
                })

            fields = {
                'usage': [k for k in fields if fields[k]]
            }
        elif identifier == 'extendedKeyUsage':
            # This extension indicates one or more purposes for which the certified
            # public key may be used, in addition to or in place of the basic
            # purposes indicated in the key usage extension.

            fields = {
                'usage': [u._name for u in extension.value]
            }
        elif identifier == 'certificatePolicies':
            # The certificate policies extension contains a sequence of one or more
            # policy information terms, each of which consists of an object
            # identifier (OID) and optional qualifiers.

            fields = {
                'policies': [{
                    'identifier': policy.policy_identifier._name,
                    'qualifiers': policy.policy_qualifiers
                } for policy in extension.value]
            }
        elif identifier == 'subjectKeyIdentifier':
            # The subject key identifier extension provides a means of identifying
            # certificates that contain a particular public key.

            fields = {
                'digest': binascii.hexlify(extension.value.digest)
            }
        elif identifier == 'authorityKeyIdentifier':
            # The authority key identifier extension provides a means of
            # identifying the public key corresponding to the private key used to
            # sign a certificate.

            fields = {
                'key_identifier': binascii.hexlify(extension.value.key_identifier)
            }
        elif identifier == 'subjectAltName':
            # The subject alternative name extension allows identities to be bound
            # to the subject of the certificate.  These identities may be included
            # in addition to or in place of the identity in the subject field of
            # the certificate.

            fields = {
                'dns': [entry.value for entry in extension.value if isinstance(entry, x509.DNSName)],
                'ip': [str(entry.value) for entry in extension.value if isinstance(entry, x509.IPAddress)]
            }
        else:
            continue

        fields['critical'] = extension.critical
        transformed_extensions[identifier] = fields

    return transformed_extensions

def parse_x509(certificate, pem_format=False):
    """
    Extracts main fields from certificate into dictionary
    While cryptography provides pretty nice high-level abstraction, I think that some thing are overcomplicated
    The function returns simple dict with most important fields

    :param certificate: Base64 certificate string as seen in Sonar's certs file
    :param pem_format: Flag specifies whether provided cert is already in PEM format
    :return: dictionary with parsed certificate fields
    """

    if not pem_format:
        pem_data = pem_format_certificate(certificate)
    parsed = x509.load_pem_x509_certificate(pem_data, default_backend())
    public_key = parsed.public_key()

    fields = {
        'version': parsed.version.value,
        'serialNumber': parsed.serial_number,
        'signatureAlgorithm': parsed.signature_algorithm_oid._name,
        'issuer': parse_subject(parsed.subject),
        'notBefore': parsed.not_valid_before,
        'notAfter': parsed.not_valid_after,
        'subject': parse_subject(parsed.issuer),
        'publicKey': {
            'keySize': (public_key.key_size if hasattr(public_key, 'key_size') else None),
            'modulus': public_key.public_numbers().n,
            'exponent': public_key.public_numbers().e
        },
        'extensions': parse_extensions(parsed.extensions),
        'signature': binascii.hexlify(parsed.signature),
        'md5Fingerprint': get_cert_fingeprint(parsed, hashes.MD5()),
        'sha1Fingerprint': get_cert_fingeprint(parsed, hashes.SHA1()),
        'sha256Fingerprint': get_cert_fingeprint(parsed, hashes.SHA256())
    }

    return fields
