'''
Common domain matching analyser.
'''
import os
import unittest

from certstream_analytics.analysers import AhoCorasickDomainMatching


class DomainMatchingTest(unittest.TestCase):
    '''
    Test the common domain matching analyser.
    '''
    def setUp(self):
        '''
        Load the mock list of common domains for testing.
        '''
        current_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(current_dir, 'opendns-top-domains.txt')) as fhandle:
            domains = [line.rstrip() for line in fhandle]

        self.analyser = AhoCorasickDomainMatching(domains)

    def test_ahocorasick(self):
        '''
        Compare some mock domains against the list of most popular domains
        using Aho-Corasick algorithm.
        '''
        cases = [
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        'google.com',
                    ],
                },
                'expected': ('google', 'store.google.com'),
                'description': 'An exact match domain',
            },

            {
                'data': {
                    'all_domains': [
                        'www.facebook.com.msg40.site',
                    ],
                },
                'expected': ('facebook', 'www.facebook.com.msg40.site'),
                'description': 'A sample phishing domain with a sub-domain match',
            },

            {
                'data': {
                    'all_domains': [
                        'login-appleid.apple.com.managesuppport.co',
                    ],
                },
                'expected': ('apple', 'login-appleid.apple.com.managesuppport.co'),
                'description': 'A sample phishing domain with a partial string match',
            },

            {
                'data': {
                    'all_domains': [
                        'socket.io',
                    ],
                },
                'expected': None,
                'description': 'An non-matching domain (not in the list of most popular domains)',
            },
        ]

        for case in cases:
            got = self.analyser.run(case['data'])
            self.assertEqual(got, case['expected'], case['description'])
