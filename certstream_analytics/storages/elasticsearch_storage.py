'''
Save certstream data into Elasticsearch so that it can be queried by Kibana
later on.
'''
import json
import requests

from datetime import datetime
from elasticsearch_dsl import connections
from elasticsearch_dsl import Document, Date, Integer, Keyword, Text
from base import Storage


class ElasticsearchStorage(Storage):
    '''
    An experiment Elasticsearch storage to keep and index the received records.
    '''
    class ElasticsearchRecord(Document):
        '''
        An Elasticsearch record as it is.
        '''

    def __init__(self, hosts=['localhost:9200'], timeout=10):
        '''
        Provide the Elasticsearch hostname (Defaults to localhost).
        '''
        connections.create_connection(hosts=hosts, timeout=timeout)

    def save(self, record):
        '''
        Move along, nothing to see here.
        '''
        pass
