'''
Test consuming the data from the great certstream.
'''
import time
import unittest

from certstream_analytics.analysers.base import Debugger
from certstream_analytics.transformers.base import CertstreamTransformer
from certstream_analytics.stream import CertstreamAnalytics


class CertstreamTest(unittest.TestCase):
    '''
    Test the way we consume data from certstream.
    '''
    DEFAULT_DELAY = 5

    def setUp(self):
        '''
        Setup the client to consume from certstream.
        '''
        self.debugger = Debugger()
        self.transformer = CertstreamTransformer()

        self.engine = CertstreamAnalytics(transformer=self.transformer,
                                          analyser=self.debugger)


    def test_consume(self):
        '''
        Start to consume some data from certstream.
        '''
        self.engine.start()

        # Wait a bit
        time.sleep(CertstreamTest.DEFAULT_DELAY)

        self.engine.stop()
        # We should see some data coming already
        self.assertTrue(self.debugger.count, 'Consuming data from certstream successfully')
