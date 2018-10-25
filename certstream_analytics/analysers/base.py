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
        In normal cases, an analyser will process the record, save the result
        into the record, and then return the updated record so that the next
        analyser can choose what to do next. Therefore, the structure of the
        record comes from CertstreamTransformer class as follows:

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
        pass


class Debugger(Analyser):
    '''
    A dummy analyser for debugging.
    '''
    def __init__(self):
        '''
        Keep track of the number of records so far for debugging purpose.
        '''
        self.count = 0

    def run(self, record):
        '''
        This is a dummy analyser that will only print out the record it processes.
        '''
        logging.info(json.dumps(record))

        # Update the number of records so far
        self.count += 1

        if 'analysers' not in record:
            record['analysers'] = []

        record['analysers'].append({
            'analyser': type(self).__name__,
            'output': self.count,
        })

        return record
