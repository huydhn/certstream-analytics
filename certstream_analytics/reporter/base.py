'''
Report the analysis result somewhere.
'''
from abc import ABCMeta, abstractmethod


# pylint: disable=no-init,too-few-public-methods
class Reporter:
    '''
    Define the template of all reporter class.
    '''
    __metaclass__ = ABCMeta

    @abstractmethod
    def publish(self, result):
        '''
        Move along, nothing to see here.
        '''
        pass
