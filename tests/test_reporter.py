'''
Various tests for the reporter module.
'''
import json
import tempfile
import unittest

from certstream_analytics.reporters import FileReporter


class FileReporterTest(unittest.TestCase):
    '''
    Test the file-based reporter.
    '''
    def setUp(self):
        '''
        Create a temporary file so that the test can write its reports into it.
        '''
        self.tmp = tempfile.NamedTemporaryFile()
        self.reporter = FileReporter(path=self.tmp.name)

    def test_report(self):
        '''
        Dump all the test reports to our temporary file.
        '''
        cases = [
            {
                'report': {
                    'all_domains': ['store.google.com', 'google.com'],
                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'domain': 'store.google.com',
                            'match': 'google',
                        },
                    ],
                },
                'description': 'Report an exact match domain',
            },

            {
                'report': {
                    'all_domains': ['www.facebook.com.msg40.site'],
                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'domain': 'www.facebook.com.msg40.site',
                            'match': 'facebook',
                        },
                    ],
                },
                'description': 'Report a phishing domain with a sub-domain match',
            },

            {
                'report': {
                    'all_domains': ['login-appleid.apple.com.managesuppport.co'],
                    'analysers': [
                        {
                            'analyser': 'AhoCorasickDomainMatching',
                            'domain': 'login-appleid.apple.com.managesuppport.co',
                            'match': 'apple',
                        },
                    ],
                },
                'description': 'Report a phishing domain with a partial string match',
            },

            {
                'report': {},
                'description': 'Report nothing and thus will be ignored',
            },
        ]

        for case in cases:
            self.reporter.publish(case['report'])

        with open(self.tmp.name) as fhandler:
            lines = fhandler.readlines()

            for index, line in enumerate(lines):
                got = json.loads(line)
                self.assertDictEqual(got, cases[index]['report'], cases[index]['description'])
