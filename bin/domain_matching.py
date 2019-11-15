#!/usr/bin/env python3
"""
A simple utility to query certstream and match its records with a list
of known domains (from OpenDNS). This script can also save the data into
downstream storage for further processing, for example, Elasticsearch.
"""
import argparse
import logging
import signal
import sys
import time

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption
from certstream_analytics.analysers import BulkDomainMarker
from certstream_analytics.analysers import IDNADecoder
from certstream_analytics.analysers import HomoglyphsDecoder
from certstream_analytics.analysers import FeaturesGenerator
from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.reporters import FileReporter
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.stream import CertstreamAnalytics

DONE = False


# pylint: disable=unused-argument
def exit_gracefully(signum, stack):
    """
    Just to be nice.
    """
    # pylint: disable=global-statement
    global DONE
    DONE = True


def init_analysers(domains_file, include_tld, matching_option):
    """
    Initialize all the analysers for matching domains. The list includes:

    - IDNA
    - Homoglyphs
    - AhoCorasick
    - Word segmentation
    - Bulk domains
    - Meta domain matching
    """
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
    """
    A simple utility to query certstream and match its records to a list of
    known domains from OpenDNS.
    """
    epilog = '''
examples:
\033[1;33m/usr/bin/domain_matching.py --elasticsearch-host elasticsearch:9200\033[0m

\033[1;33m/usr/bin/domain_matching.py --dump-location certstream.txt\033[0m

\033[1;33m/usr/bin/domain_matching.py --domains opendns-top-domains.txt\033[0m

Consume data from Certstream and does its magic.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--domains',
                        help='the list of domains to match with (e.g. opendns-top-domains.txt)')

    parser.add_argument('--elasticsearch-host',
                        help='set the Elasticsearch host to store the records from Certstream')

    parser.add_argument('--dump-location',
                        help='where to dump the records from Certstream')

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
    reporter = FileReporter(path=args.dump_location) if args.dump_location else None
    storage = ElasticsearchStorage(hosts=[args.elasticsearch_host]) if args.elasticsearch_host else None

    engine = CertstreamAnalytics(transformer=transformer,
                                 storages=storage,
                                 analysers=analysers,
                                 reporters=reporter)
    engine.start()

    while not DONE:
        time.sleep(1)

    engine.stop()


if __name__ == '__main__':
    # Make sure that we can exit gracefully
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    run()
