'''
Various tests for the reporter module.
'''
import json
import tempfile
import unittest

from certstream_analytics.reporter import FileReporter


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
                'report': {'match': 'google', 'domain': 'store.google.com'},
                'description': 'Report an exact match domain',
            },

            {
                'report': {'match': 'facebook', 'domain': 'www.facebook.com.msg40.site'},
                'description': 'Report a phishing domain with a sub-domain match',
            },

            {
                'report': {'match': 'apple', 'domain': 'login-appleid.apple.com.managesuppport.co'},
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
