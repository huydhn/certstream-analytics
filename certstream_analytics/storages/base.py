'''
Save certstream data into various storages, streaming or not.
'''
from abc import ABCMeta, abstractmethod


# pylint: disable=no-init,too-few-public-methods
class Storage:
    '''
    Define the template of all analyser class.
    '''
    __metaclass__ = ABCMeta

    @abstractmethod
    def save(self, record):
        '''
        Move along, nothing to see here.
        '''
        pass
