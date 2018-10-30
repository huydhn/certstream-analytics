'''
Transform the certificate data from certstream before passing it to the
processing pipeline.
'''
import json
import logging
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
    A dummy transformer that doesn't do anything.
    '''
    def apply(self, raw):
        '''
        Move along, nothing to see here.
        '''
        return raw


class CertstreamTransformer(Transformer):
    '''
    Transform data from certstream into something readily consumable by the
    processing pipeline.
    '''
    def apply(self, raw):
        '''
        The format of the message from certstream can be found at their github
        documentation.

        So far, we are only interested in the domain names, the timestamps, and
        probably the content of the subject. So the returned stucture is as
        follows:

            {
                # These fields are extracted from certstream
                cert_index: INTEGER,
                seen: TIMESTAMP,
                chain: [
                    ORGANIZATION
                ],
                not_before: TIMESTAMP,
                not_after: TIMESTAMP,
                all_domains: [
                    SAN
                ],

                # This is a place holder field which are used later by the
                # analysers. Each analyser will append its result here.
                analysers: [
                    {
                        analyser: ANALYSER NAME,
                        output: ANYTHING GOESE HERE,
                    },
                ],
            }
        '''
        logging.debug(json.dumps(raw))

        filtered = {
            'cert_index': raw['data']['cert_index'],
            'seen': raw['data']['seen'],
            'chain': [],

            # The analyser result will be stored here later on
            'analysers': [],
        }

        interested_fields = ['not_before', 'not_after', 'all_domains']

        if raw['data']['leaf_cert']['all_domains']:
            filtered.update({k: raw['data']['leaf_cert'][k] for k in interested_fields})
            return filtered

        return None
