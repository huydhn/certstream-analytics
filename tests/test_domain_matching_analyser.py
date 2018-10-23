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
                'expected': [
                    {
                        'analyser': 'AhoCorasickDomainMatching',
                        'match': 'google',
                        'domain': 'store.google.com'
                    },
                ],
                'description': 'An exact match domain',
            },

            {
                'data': {
                    'all_domains': [
                        'www.facebook.com.msg40.site',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'AhoCorasickDomainMatching',
                        'match': 'facebook',
                        'domain': 'www.facebook.com.msg40.site'
                    },
                ],
                'description': 'A sample phishing domain with a sub-domain match',
            },

            {
                'data': {
                    'all_domains': [
                        'login-appleid.apple.com.managesuppport.co',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'AhoCorasickDomainMatching',
                        'match': 'apple',
                        'domain': 'login-appleid.apple.com.managesuppport.co'
                    },
                ],
                'description': 'A sample phishing domain with a partial string match',
            },

            {
                'data': {
                    'all_domains': [
                        'socket.io',
                    ],
                },
                'expected': [],
                'description': 'A non-matching domain (not in the list of most popular domains)',
            },

            {
                'data': {
                    'all_domains': [
                        'www.foobar2000.com',
                    ],
                },
                'expected': [],
                'description': 'A non-matching domain (excluded pattern)',
            }
        ]

        for case in cases:
            got = self.analyser.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])
