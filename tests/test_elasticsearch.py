'''
Save some dummy records into Elasticsearch.
'''
import os
import json
import unittest

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.storages import ElasticsearchStorage


class ElasticsearchTest(unittest.TestCase):
    '''
    Test the way we save data into Elasticsearch.
    '''

    def setUp(self):
        '''
        Setup the client to consume from certstream and save the data into
        Elasticsearch
        '''
        elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'localhost:9200')

        self.transformer = CertstreamTransformer()
        self.storage = ElasticsearchStorage(hosts=[elasticsearch_host])
        self.search = Search(using=Elasticsearch(elasticsearch_host), index='certstream-*')

    def test_save(self):
        '''
        Start to save certstream data into Elasticsearch.
        '''
        current_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(current_dir, 'samples.json')) as fhandle:
            samples = json.load(fhandle)

        for sample in samples:
            filtered = self.transformer.apply(sample)
            self.storage.save(filtered)

        for sample in samples:
            domain = sample['data']['leaf_cert']['all_domains'][0]
            # Look for the record in Elasticsearch
            query = Q('multi_match', query=domain, fields=['domain', 'san'])
            response = self.search.query(query).execute()

            self.assertEqual(response.hits.total, 1,
                             'The record has been indexed in Elasticsearch')
            self.assertIn(response.hits[0].domain, sample['data']['leaf_cert']['all_domains'],
                          'The correct record is returned')
