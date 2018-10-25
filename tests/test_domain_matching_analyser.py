'''
Common domain matching analyser.
'''
import os
import unittest

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentationAnalyser
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption


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
        self.domain_matching_analyser = DomainMatching()

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
                            'store.google.com': ['google.com'],
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
                            'www.facebook.com.msg40.site': ['facebook.com'],
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
                            'login-appleid.apple.com.managesuppport.co': ['apple.com'],
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
                            'store.google.com': ['store', 'google', 'com'],
                            'google.com': ['google', 'com'],
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
                            'www.facebook.com.msg40.site': ['www', 'facebook', 'com', 'msg40', 'site'],
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
                                'suppport',
                                'co'
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
                            'arch.mappleonline.com': ['arch', 'm', 'apple', 'online', 'com'],
                        },
                    },
                ],
                'description': 'Failed to segment the word correctly',
            },
        ]

        for case in cases:
            got = self.wordsegmentation_analyser.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])

    def test_domain_matching(self):
        '''
        Combine the result of all domain matching analysers into one.
        '''
        cases = [
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        'google.com',
                    ],

                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'output': {
                                'store.google.com': ['google.com'],
                            },
                        },

                        {
                            'analyser': 'WordSegmentationAnalyser',
                            'output': {
                                'store.google.com': ['store', 'google', 'com'],
                                'google.com': ['google', 'com'],
                            },
                        },
                    ],
                },
                'expected': [
                    {
                        'analyser': 'AhoCorasickDomainMatching',
                        'output': {
                            'store.google.com': ['google.com'],
                        },
                    },

                    {
                        'analyser': 'WordSegmentationAnalyser',
                        'output': {
                            'store.google.com': ['store', 'google', 'com'],
                            'google.com': ['google', 'com'],
                        },
                    },

                    {
                        'analyser': 'DomainMatching',
                        'output': {
                            'store.google.com': ['google.com'],
                        },
                    },
                ],
                'description': 'A legit domain',
            },

            {
                'data': {
                    'all_domains': [
                        'login-appleid.apple.com.managesuppport.co',
                    ],

                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'output': {
                                'login-appleid.apple.com.managesuppport.co': ['apple.com'],
                            },
                        },

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
                },
                'expected': [
                    {
                        'analyser': 'AhoCorasickDomainMatching',
                        'output': {
                            'login-appleid.apple.com.managesuppport.co': ['apple.com'],
                        },
                    },

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

                    {
                        'analyser': 'DomainMatching',
                        'output': {
                            'login-appleid.apple.com.managesuppport.co': ['apple.com']
                        },
                    },
                ],
                'description': 'Find a matching phishing domain (include TLD, same order)',
            },

            # Need more test cases here for other matching algorithms besides the
            # default one
        ]

        for case in cases:
            got = self.domain_matching_analyser.run(case['data'])
            self.assertCountEqual(got['analysers'], case['expected'], case['description'])
