'''
Common domain matching analyser.
'''
import os
import unittest

from certstream_analytics.analysers import CommonDomainMatching


class CommonDomainMatchingTest(unittest.TestCase):
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

        self.analyser = CommonDomainMatching(domains)

    def test_save(self):
        '''
        Compare some mock domains against the list of most popular domains.
        '''
        cases = [
            {
                'data': {
                    'all_domains': [
                        'google.com',
                        'store.google.com',
                    ]
                },

                'expected': 'google.com',

                'description': 'An exact match domain',
            },

            {
                'data': {
                    'all_domains': [
                        'www.facebook.com.msg40.site',
                    ]
                },

                'expected': 'www.facebook.com.msg40.site',
                'description': 'An sample phishing domain with a partial match',
            },

            {
                'data': {
                    'all_domains': [
                        'socket.io',
                    ]
                },

                'expected': None,
                'description': 'An non-matching domain',
            },
        ]

        for case in cases:
            got = self.analyser.run(case['data'])
            self.assertEqual(got, case['expected'], case['description'])
