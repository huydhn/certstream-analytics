'''
Common domain matching analyser.
'''
import os
import unittest

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentationAnalyser


class DomainMatchingTest(unittest.TestCase):
    '''
    Test all the common domain matching analysers.
    '''
    def setUp(self):
        '''
        Load the mock list of common domains for testing.
        '''
        current_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(current_dir, 'opendns-top-domains.txt')) as fhandle:
            domains = [line.rstrip() for line in fhandle]

        self.ahocorasick_analyser = AhoCorasickDomainMatching(domains)
        self.wordsegmentation_analyser = WordSegmentationAnalyser()

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
                        'output': {
                            'store.google.com': ['google'],
                        },
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
                        'output': {
                            'www.facebook.com.msg40.site': ['facebook'],
                        },
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
                        'output': {
                            'login-appleid.apple.com.managesuppport.co': ['apple'],
                        },
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
            got = self.ahocorasick_analyser.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])

    def test_wordsegmentation(self):
        '''
        Try to segment some domains and check the result.
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
                        'analyser': 'WordSegmentationAnalyser',
                        'output': {
                            'store.google.com': ['store', 'google'],
                            'google.com': ['google'],
                        },
                    },
                ],
                'description': 'A legit domain',
            },

            {
                'data': {
                    'all_domains': [
                        'www.facebook.com.msg40.site',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'WordSegmentationAnalyser',
                        'output': {
                            'www.facebook.com.msg40.site': ['www', 'facebook', 'com', 'msg40'],
                        },
                    },
                ],
                'description': 'Word segmentation using the domain separator (dot)',
            },

            {
                'data': {
                    'all_domains': [
                        'login-appleid.apple.com.managesuppport.co',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'WordSegmentationAnalyser',
                        'output': {
                            'login-appleid.apple.com.managesuppport.co': [
                                'login',
                                'apple',
                                'id',
                                'apple',
                                'com',
                                'manage',
                                'suppport'
                            ],
                        },
                    },
                ],
                'description': 'Word segmentation using dictionary',
            },

            {
                'data': {
                    'all_domains': [
                        'arch.mappleonline.com',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'WordSegmentationAnalyser',
                        'output': {
                            'arch.mappleonline.com': ['arch', 'm', 'apple', 'online'],
                        },
                    },
                ],
                'description': 'Failed to segment the word correctly',
            },
        ]

        for case in cases:
            got = self.wordsegmentation_analyser.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])
