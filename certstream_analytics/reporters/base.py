'''
Report the analysis result somewhere.
'''
import json
from abc import ABCMeta, abstractmethod


# pylint: disable=no-init,too-few-public-methods
class Reporter:
    '''
    Define the template of all reporter class.
    '''
    __metaclass__ = ABCMeta

    @abstractmethod
    def publish(self, report):
        '''
        Move along, nothing to see here.
        '''
        pass


class FileReporter(Reporter):
    '''
    Simply print the report to a file.
    '''
    def __init__(self, path):
        '''
        Note that an exception will be raised if the path is not valid or writable.
        '''
        self.path = path

    def publish(self, report):
        '''
        This is a very basic reporter that will only print out the record it receives
        to a plain text file.
        '''
        if not report:
            return

        with open(self.path, 'a') as fhandler:
            print(json.dumps(report), file=fhandler)
