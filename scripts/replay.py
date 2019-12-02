#!/usr/bin/env python3
'''
Replay a stream of records from certstream to test the processing pipeline.
'''
import argparse
import json
import logging
import sys

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption
from certstream_analytics.analysers import BulkDomainMarker
from certstream_analytics.analysers import IDNADecoder
from certstream_analytics.analysers import HomoglyphsDecoder
from certstream_analytics.analysers import FeaturesGenerator
from certstream_analytics.reporters import FileReporter
from certstream_analytics.reporters import CoNLL
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.transformers import CertstreamTransformer


SUPPORTED_REPORTERS = {
    'file': lambda location: FileReporter(path=location),
    'conll': lambda location: CoNLL(path=location)
}

SUPPORTED_STORAGES = {
    'elasticsearch': lambda host: ElasticsearchStorage(hosts=[host])
}


def init_analysers(domains_file, include_tld, matching_option):
    '''
    Initialize all the analysers for matching domains. The list includes:

    - IDNA
    - Homoglyphs
    - AhoCorasick
    - Word segmentation
    - Bulk domains
    - Meta domain matching
    '''
    with open(domains_file) as fhandle:
        domains = [line.rstrip() for line in fhandle]

    # Initialize all analysers. Note that their order is important cause they
    # will be executed in that order
    return [
        IDNADecoder(),
        HomoglyphsDecoder(greedy=False),
        AhoCorasickDomainMatching(domains=domains),
        WordSegmentation(),
        BulkDomainMarker(),
        DomainMatching(include_tld=include_tld, option=matching_option),
        FeaturesGenerator(),
    ]


def run():
    '''
    A simple utility to replay certstream and match the records to a list of
    known domains from OpenDNS. It also generates several features for each
    domain such as the domain length.
    '''
    epilog = '''
examples:
\033[1;33m/usr/bin/replay.py --replay certstream.txt\033[0m

\033[1;33m/usr/bin/replay.py --storage-host elasticsearch:9200\033[0m

\033[1;33m/usr/bin/domain_matching.py --json certstream.txt --conll conll.txt\033[0m

\033[1;33m/usr/bin/replay.py --domains opendns-top-domains.txt\033[0m

Replay data from certstream.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--replay',
                        help='the list of records from certstream (one per line)')

    parser.add_argument('--domains',
                        help='the list of domains to match with (e.g. opendns-top-domains.txt)')

    parser.add_argument('--elasticsearch-host',
                        help='set the Elasticsearch host to store the records from Certstream')

    parser.add_argument('--json',
                        help='where to dump the records from Certstream in JSON format')

    parser.add_argument('--conll',
                        help='where to dump the word segmentation output in CoNLL-U format')


    try:
        args = parser.parse_args()
    # pylint: disable=broad-except
    except Exception as error:
        logging.error(error)
        # some errors occur when parsing the arguments, show the usage
        parser.print_help()
        # then quit
        sys.exit(1)

    transformer = CertstreamTransformer()
    analysers = init_analysers(domains_file=args.domains,
                               include_tld=True,
                               matching_option=DomainMatchingOption.ORDER_MATCH)
    storage = ElasticsearchStorage(hosts=[args.elasticsearch_host]) if args.elasticsearch_host else None

    json_reporter = FileReporter(path=args.json) if args.json else None
    conll_reporter = CoNLL(path=args.conll) if args.conll else None

    with open(args.replay) as fhandler:
        for raw in fhandler:
            try:
                record = json.loads(raw)
            except json.decoder.JSONDecodeError:
                continue

            if storage:
                storage.save(record)

            # Clear all existing analysers
            record['analysers'] = []
            for analyser in analysers:
                # Run something here
                record = analyser.run(record)

            if json_reporter:
                json_reporter.publish(record)

            if conll_reporter:
                conll_reporter.publish(record)


if __name__ == '__main__':
    run()
