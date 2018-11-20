'''
Common domain matching analyser.
'''
import copy
import os
import unittest

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption


class DomainMatchingTest(unittest.TestCase):
    '''
    Test all the common domain matching analysers.
    '''
    def test_ahocorasick(self):
        '''
        Compare some mock domains against the list of most popular domains
        using Aho-Corasick algorithm.
        '''
        # Load the mock list of common domains for testing.
        current_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(current_dir, 'opendns-top-domains.txt')) as fhandle:
            domains = [line.rstrip() for line in fhandle]

        ahocorasick_analyser = AhoCorasickDomainMatching(domains)

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
            },

            {
                'data': {
                    'all_domains': [
                        'autodiscover.blablabla.com',
                    ],
                },
                'expected': [],
                'description': 'Match a ignored pattern',
            },
        ]

        for case in cases:
            got = ahocorasick_analyser.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])

    def test_wordsegmentation(self):
        '''
        Try to segment some domains and check the result.
        '''
        wordsegmentation = WordSegmentation()

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
                        'analyser': 'WordSegmentation',
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
                        'analyser': 'WordSegmentation',
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
                        'analyser': 'WordSegmentation',
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
                        'analyser': 'WordSegmentation',
                        'output': {
                            'arch.mappleonline.com': ['arch', 'm', 'apple', 'online', 'com'],
                        },
                    },
                ],
                'description': 'Failed to segment the word correctly',
            },

            {
                'data': {
                    'all_domains': [
                        'www.freybrothersinc.com',
                    ],
                },
                'expected': [
                    {
                        'analyser': 'WordSegmentation',
                        'output': {
                            'www.freybrothersinc.com': ['www', 'frey', 'brothers', 'com'],
                        },
                    },
                ],
                'description': 'Ignore certain stop words (inc) when doing segmentation',
            },
        ]

        for case in cases:
            got = wordsegmentation.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])

    def test_domain_matching(self):
        '''
        Combine the result of all domain matching analysers into one.
        '''
        # The first option decides if the TLD is included in the match
        options = [
            (True, DomainMatchingOption.SUBSET_MATCH),
            (False, DomainMatchingOption.SUBSET_MATCH),
            (True, DomainMatchingOption.ORDER_MATCH),
            (False, DomainMatchingOption.ORDER_MATCH),
        ]

        analysers = {o: DomainMatching(include_tld=o[0], option=o[1]) for o in options}

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
                            'analyser': 'WordSegmentation',
                            'output': {
                                'store.google.com': ['store', 'google', 'com'],
                                'google.com': ['google', 'com'],
                            },
                        },
                    ],
                },
                'expected': {
                    (True, DomainMatchingOption.SUBSET_MATCH): [],
                    (False, DomainMatchingOption.SUBSET_MATCH): [],
                    (True, DomainMatchingOption.ORDER_MATCH): [],
                    (False, DomainMatchingOption.ORDER_MATCH): [],
                },
                'description': 'A legit domain so it will be skipped (no match reported)',
            },

            {
                'data': {
                    'all_domains': [
                        'login-appleid.managesuppport.com',
                    ],

                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'output': {
                                'login-appleid.managesuppport.com': ['apple.com'],
                            },
                        },

                        {
                            'analyser': 'WordSegmentation',
                            'output': {
                                'login-appleid.managesuppport.com': [
                                    'login',
                                    'apple',
                                    'id',
                                    'manage',
                                    'suppport'
                                ],
                            },
                        },
                    ],
                },
                'expected': {
                    (True, DomainMatchingOption.SUBSET_MATCH): [],
                    (False, DomainMatchingOption.SUBSET_MATCH): [
                        {
                            'analyser': 'DomainMatching',
                            'output': {
                                'login-appleid.managesuppport.com': ['apple.com']
                            },
                        },
                    ],
                    (True, DomainMatchingOption.ORDER_MATCH): [],
                    (False, DomainMatchingOption.ORDER_MATCH): [
                        {
                            'analyser': 'DomainMatching',
                            'output': {
                                'login-appleid.managesuppport.com': ['apple.com']
                            },
                        },
                    ],
                },
                'description': 'Find a matching phishing domain',
            },

            {
                'data': {
                    'all_domains': [
                        'djunprotected.com',
                        'www.djunprotected.com'
                    ],

                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'output': {
                                'djunprotected.com': ['ted.com']
                            }
                        },

                        {
                            'analyser': 'WordSegmentation',
                            'output': {
                                'djunprotected.com': ['dj', 'unprotected', 'com'],
                                'www.djunprotected.com': ['www', 'dj', 'unprotected', 'com']
                            }
                        },
                    ],
                },
                'expected': {
                    (True, DomainMatchingOption.SUBSET_MATCH): [],
                    (False, DomainMatchingOption.SUBSET_MATCH): [],
                    (True, DomainMatchingOption.ORDER_MATCH): [],
                    (False, DomainMatchingOption.ORDER_MATCH): [],
                },
                'description': 'Find a matching phishing domain',
            },
        ]

        for case in cases:
            for option, analyser in analysers.items():
                expected = copy.deepcopy(case['data']['analysers'])
                expected.extend(case['expected'][option])

                got = analyser.run(case['data'])
                self.assertListEqual(got['analysers'], expected,
                                     '{} ({})'.format(case['description'], option))
