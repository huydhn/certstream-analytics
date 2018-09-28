'''
Transform the certificate data from certstream before passing it to the
processing pipeline.
'''
from abc import ABCMeta, abstractmethod


# pylint: disable=no-init,too-few-public-methods
class Transformer:
    '''
    Define the template of all transformer class.
    '''
    __metaclass__ = ABCMeta

    @abstractmethod
    def apply(self, raw):
        '''
        Move along, nothing to see here.
        '''
        pass


class PassthroughTransformer(Transformer):
    '''
    An experiment transformer that doesn't do anything.
    '''
    def apply(self, raw):
        '''
        Move along, nothing to see here.
        '''
        return raw


class CertstreamTransformer(Transformer):
    '''
    Transform data from certstream into something readily usable by the
    processing pipeline.
    '''
    def apply(self, raw):
        '''
        So far, we are only interested in the domain names, the timestamps, and
        probably the content of the subject as well.

        The format of the message from certstream can be found at their github
        documentation.
        '''
        interested_fields = ['not_before', 'not_after', 'all_domains']

        if raw['data']['leaf_cert']['all_domains']:
            return {k: raw['data']['leaf_cert'][k] for k in interested_fields}

        return None
