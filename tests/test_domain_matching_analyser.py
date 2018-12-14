'''
Common domain matching analyser.
'''
import copy
import os
import unittest

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption
from certstream_analytics.analysers import BulkDomainMarker
from certstream_analytics.analysers import IDNADecoder
from certstream_analytics.analysers import HomoglyphsDecoder


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

    def test_bulk_domain_marker(self):
        '''
        Test the bulk domain analyser.
        '''
        bulky = BulkDomainMarker()

        cases = [
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        'google.com',
                    ],
                },
                'expected':  [
                    {'analyser': 'BulkDomainMarker', 'output': False}
                ],
                'description': 'Not a bulk record',
            },
            {
                'data': {
                    'all_domains': [
                        'a.com',
                        'b.com',
                        'c.com',
                        'd.com',
                        'e.com',
                        'f.com',
                        'g.com',
                        'h.com',
                        'i.com',
                        'j.com',
                        'k.com',
                        'l.com',
                        'm.com',
                        'n.com',
                        'o.com',
                    ],
                },
                'expected':  [
                    {'analyser': 'BulkDomainMarker', 'output': True}
                ],
                'description': 'Mark a bulk record',
            },
        ]

        for case in cases:
            got = bulky.run(case['data'])
            self.assertListEqual(got['analysers'], case['expected'], case['description'])

    def test_idn_decoder(self):
        '''
        Test the IDNA decoder.
        '''
        decoder = IDNADecoder()

        cases = [
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        'google.com',
                    ],
                },
                'expected':  [
                    'store.google.com',
                    'google.com',
                ],
                'description': 'There is no domain in IDNA format',
            },
            {
                'data': {
                    'all_domains': [
                        'xn--f1ahbgpekke1h.xn--p1ai',
                        'tigrobaldai.lt'
                    ],
                },
                'expected':  [
                    'укрэмпужск.рф',
                    'tigrobaldai.lt'
                ],
                'description': 'Convert some domains in IDNA format',
            },
            {
                'data': {
                    'all_domains': [
                        'xn--foobar.xn--me',
                    ],
                },
                'expected':  [
                    'xn--foobar.xn--me',
                ],
                'description': 'Handle an invalid IDNA string',
            },
            {
                'data': {
                    'all_domains': [
                        '*.xn---35-5cd3cln6a9bzb.xn--p1ai',
                        '*.nl-dating-vidkid.com',
                    ],
                },
                'expected':  [
                    '*.отмычка-35.рф',
                    '*.nl-dating-vidkid.com',
                ],
                'description': 'Handle an invalid code point',
            },
        ]

        for case in cases:
            got = decoder.run(case['data'])
            self.assertListEqual(got['all_domains'], case['expected'], case['description'])

    def test_homoglyphs_decoder(self):
        '''
        Test the homoglyphs decoder.
        '''
        cases = [
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        '*.google.com',
                    ],
                },
                'greedy': False,
                'expected':  [
                    'store.google.com',
                    '*.google.com',
                ],
                'description': 'Normal domains in ASCII',
            },
            {
                'data': {
                    'all_domains': [
                        'store.google.com',
                        '*.google.com',
                    ],
                },
                'greedy': True,
                'expected':  [
                    'store.google.com',
                    'store.google.corn',
                    'store.googie.com',
                    'store.googie.corn',
                    '*.google.com',
                    '*.google.corn',
                    '*.googie.com',
                    '*.googie.corn'
                ],
                'description': 'Normal domains in ASCII with a greedy decoder',
            },
            {
                'data': {
                    'all_domains': [
                        'укрэмпужск.рф',
                        'tigrobaldai.lt',
                    ],
                },
                'greedy': False,
                'expected':  [
                    'yкpэмпyжcк.pф',
                    'tigrobaldai.lt',
                ],
                'description': 'Normal domains in Unicode',
            },
            {
                'data': {
                    'all_domains': [
                        'укрэмпужск.рф',
                        'tigrobaldai.lt',
                    ],
                },
                'greedy': True,
                'expected':  [
                    'yкpэмпyжcк.pф',
                    'tigrobaldai.lt',
                    'tigrobaldai.it',
                    'tigrobaidai.lt',
                    'tigrobaidai.it',
                ],
                'description': 'Normal domains in Unicode with a greedy decoder',
            },
            {
                'data': {
                    'all_domains': [
                        # MATHEMATICAL MONOSPACE SMALL P 1D699
                        '*.𝗉aypal.com',

                        # MATHEMATICAL SAN-SERIF BOLD SMALL RHO
                        'phishing.𝗉ay𝞀al.com',
                    ],
                },
                'greedy': False,
                'expected': [
                    '*.paypal.com',
                    'phishing.paypal.com',
                ],
                'description': 'Phishing example in confusable homoglyphs'
            },
            {
                'data': {
                    'all_domains': [
                        # MATHEMATICAL MONOSPACE SMALL P 1D699
                        '*.𝗉aypal.com',

                        # MATHEMATICAL SAN-SERIF BOLD SMALL RHO
                        'phishing.𝗉ay𝞀al.com',
                    ],
                },
                'greedy': True,
                'expected': [
                    '*.paypal.com',
                    '*.paypal.corn',
                    '*.paypai.com',
                    '*.paypai.corn',
                    'phishing.paypal.com',
                    'phishing.paypal.corn',
                    'phishing.paypai.com',
                    'phishing.paypai.corn',
                ],
                'description': 'Phishing example in confusable homoglyphs with a greedy decoder'
            },
        ]

        for case in cases:
            decoder = HomoglyphsDecoder(greedy=case['greedy'])

            got = decoder.run(case['data'])
            self.assertListEqual(got['all_domains'], case['expected'], case['description'])
