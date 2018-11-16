'''
Mark the record that has tons of SAN domains in it. Most of the time, they are
completely unrelated domains and probably the result of some bulk registration
process. Benign or not, they are still suspicious and probably spam.
'''
from .base import Analyser


class BulkDomainMarker(Analyser):
    '''
    Mark the record if the number of SAN domains is larger than a certain
    threshold. It will also verify the similarity among these domains. A
    lower similarity score means these domains are totally unrelated.
    '''
    # TODO: take a histogram here and find out the suitable value for this
    BULK_DOMAIN_THRESHOLD = 15


    def __init__(self, threshold=BulkDomainMarker.BULK_DOMAIN_THRESHOLD):
        '''
        Set the threshold to mark the record as a bulk record.
        '''
        self.threshold = threshold
