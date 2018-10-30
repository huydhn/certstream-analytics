'''
Save certstream data into Elasticsearch so that it can be queried by Kibana
later on.
'''
from datetime import datetime
from elasticsearch_dsl import connections, analyzer
from elasticsearch_dsl import Document, Date, Text, Keyword

from .base import Storage

ANALYZER = analyzer('standard_analyzer',
                    tokenizer='standard_tokenizer',
                    filter=['lowercase'])


# pylint: disable=too-few-public-methods
class ElasticsearchStorage(Storage):
    '''
    An experiment Elasticsearch storage to keep and index the received records.
    '''
    class Record(Document):
        '''
        An Elasticsearch record as it is.
        '''
        timestamp = Date(default_timezone='UTC')

        # As reported by certstream
        seen = Date(default_timezone='UTC')

        # The domain time to live
        not_before = Date(default_timezone='UTC')
        not_after = Date(default_timezone='UTC')

        # The domain and its alternative names
        domain = Text(analyzer=ANALYZER, fields={'raw': Keyword()})
        san = Text(analyzer=ANALYZER, fields={'raw': Keyword()})

        # The issuer
        chain = Text(analyzer=ANALYZER, fields={'raw': Keyword()})

        class Index:
            '''
            Use daily indices.
            '''
            name = 'certstream-*'

        # pylint: disable=arguments-differ
        def save(self, **kwargs):
            '''
            Magically save the record in Elasticsearch.
            '''
            self.timestamp = datetime.now()
            # Override the index to go to the proper timeslot
            kwargs['index'] = self.timestamp.strftime('certstream-%Y.%m.%d')

            return super().save(**kwargs)

    def __init__(self, hosts, timeout=10):
        '''
        Provide the Elasticsearch hostname (Defaults to localhost).
        '''
        connections.create_connection(hosts=hosts, timeout=timeout)

    def save(self, record):
        '''
        Save the certstream record in Elasticsearch.
        '''
        elasticsearch_record = ElasticsearchStorage.Record(meta={'id': record['cert_index']})

        # In miliseconds
        elasticsearch_record.seen = int(record['seen'] * 1000)
        elasticsearch_record.not_before = int(record['not_before'] * 1000)
        elasticsearch_record.not_after = int(record['not_after'] * 1000)

        # Elasticsearch will parse and index the domain and all its alternative names
        elasticsearch_record.domain = record['all_domains'][0]
        elasticsearch_record.san = record['all_domains'][1:]

        elasticsearch_record.save()
