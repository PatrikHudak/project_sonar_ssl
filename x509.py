#!/usr/bin/env python

"""
x509.py
~~~~~~~~
CLI for parsing Sonar SSL certificates
"""

import pprint

from parser import parse_x509

b64_certificate = raw_input('Paste base64 encoded certificate: ')
parsed_cert = parse_x509(b64_certificate)
pprint.pprint(parsed_cert)
