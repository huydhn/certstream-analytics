'''
Analyse the certificate data from certstream.
'''
import json
import logging
from abc import ABCMeta, abstractmethod


# pylint: disable=no-init,too-few-public-methods
class Analyser:
    '''
    Define the template of all analyser class.
    '''
    __metaclass__ = ABCMeta

    @abstractmethod
    def run(self, record):
        '''
        Move along, nothing to see here.
        '''
        pass


class Debugger(Analyser):
    '''
    An experiment analyser to debug the received records.
    '''
    def __init__(self):
        '''
        Keep track of the number of records so far for debugging purpose.
        '''
        self.count = 0

    def run(self, record):
        '''
        This is an experiment analyser and it will only print out the record
        to be analysed.
        '''
        logging.info(json.dumps(record))

        # Update the number of records so far
        self.count += 1
