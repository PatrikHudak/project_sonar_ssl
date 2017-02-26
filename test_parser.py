#!/usr/bin/env python

import datetime
import unittest

import parser

class ParserTest(unittest.TestCase):
    def setUp(self):
        with open('test_data/digicert.pem') as fh:
            self.pem_data = fh.read()
        self.stripped_pem = ''.join(self.pem_data.strip().split('\n')[1:-1])
        self.parsed = parser.parse_x509(self.stripped_pem)

    def test_pem_transformation(self):
        pem_format = parser.pem_format_certificate(self.stripped_pem)
        pem_format_split = pem_format.split('\n')
        self.assertEquals(pem_format_split[0], '-----BEGIN CERTIFICATE-----')
        self.assertEquals(pem_format_split[-1], '-----END CERTIFICATE-----')
        self.assertEquals(len(pem_format.split('\n')), 28)
        self.assertEquals(len(pem_format_split[1]), 64)

    def test_validity(self):
        # Not Before: Oct 22 12:00:00 2013 GMT
        self.assertEquals(self.parsed['notBefore'], datetime.datetime(2013, 10, 22, 12, 0, 0, 0))
        # Not After : Oct 22 12:00:00 2028 GMT
        self.assertEquals(self.parsed['notAfter'], datetime.datetime(2028, 10, 22, 12, 0, 0, 0))

    def test_version(self):
        self.assertEquals(self.parsed['version'], 2)

    def test_serial_number(self):
        self.assertEqual(self.parsed['serialNumber'], 0xc79a944b08c11952092615fe26b1d83L)

    def test_fingerprints(self):
        self.assertEqual(self.parsed['md5Fingerprint'], '253ea87bf67d57241524f00e457768ac')
        self.assertEqual(self.parsed['sha1Fingerprint'], '7e2f3a4f8fe8fa8a5730aeca029696637e986f3f')
        self.assertEqual(self.parsed['sha256Fingerprint'], '403e062a2653059113285baf80a0d4ae422c848c9f78fad01fc94bc5b87fef1a')

    def test_issuer(self):
        issuer = self.parsed['issuer']
        self.assertEqual(issuer['commonName'], u'DigiCert SHA2 Extended Validation Server CA')
        self.assertEqual(issuer['countryName'], u'US')
        self.assertEqual(issuer['organizationName'], u'DigiCert Inc')
        self.assertEqual(issuer['organizationalUnitName'], u'www.digicert.com')
        self.assertFalse('stateOrProvinceName' in issuer)
        self.assertFalse('localityName' in issuer)

    def test_subject(self):
        subject = self.parsed['subject']
        self.assertEqual(subject['commonName'], u'DigiCert High Assurance EV Root CA')
        self.assertEqual(subject['countryName'], u'US')
        self.assertEqual(subject['organizationName'], u'DigiCert Inc')
        self.assertEqual(subject['organizationalUnitName'], u'www.digicert.com')
        self.assertFalse('stateOrProvinceName' in subject)
        self.assertFalse('localityName' in subject)

    def test_signature(self):
        cert_signature = ('9db6d09086e18602edc5a0f0341c74c18d76cc860aa8f04a8a42'
                          'd63fc8a94dad7c08ade6b650b8a21a4d8807b12921dce7dac63c'
                          '21e0e3114970ac7a1d01a4ca113a57ab7d572a4074fdd31d8518'
                          '50df574775a17d55202e473750728c7f821bd2628f2d035adac3'
                          'c8a1ce2c52a20063eb73ba71c84927239764859e380ead63683c'
                          'ba52815879a32c0cdfde6deb31f2baa07c6cf12cd4e1bd778437'
                          '03ce32b5c89a811a4a924e3b469a85fe83a2f99e8ca3cc0d5eb3'
                          '3dcf04788f14147b329cc700a65cc4b5a1558d5a5668a42270aa'
                          '3c8171d99da8453bf4e5f6a251ddc77b62e86f0c74ebb8daf8bf'
                          '870d795091909b183b915927f1352813ab267ed5f77a')

        self.assertEqual(self.parsed['signatureAlgorithm'], 'sha256WithRSAEncryption')
        self.assertEqual(self.parsed['signature'], cert_signature)

    def test_public_key(self):
        public_key = self.parsed['publicKey']
        self.assertEqual(public_key['exponent'], 65537)
        self.assertEqual(public_key['keySize'], 2048)

    def test_extensions(self):
        pass

if __name__ == '__main__':
    unittest.main()