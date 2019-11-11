#!/usr/bin/env python3
'''
A simple utility to query certstream and match its records with a list
of known domains (from OpenDNS). This script can also save the data into
downstream storage for further processing, for example, Elasticsearch.
'''
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

SUPPORTED_REPORTERS = {
    'file': lambda location: FileReporter(path=location)
}

SUPPORTED_STORAGES = {
    'elasticsearch': lambda host: ElasticsearchStorage(hosts=[host])
}


# pylint: disable=unused-argument
def exit_gracefully(signum, stack):
    '''
    Just to be nice.
    '''
    # pylint: disable=global-statement
    global DONE
    DONE = True


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
    A simple utility to query certstream and match its records to a list of
    known domains from OpenDNS.
    '''
    epilog = '''
examples:
\033[1;33m/usr/bin/domain_matching.py --storage-host elasticsearch:9200 --storage elasticsearch\033[0m

\033[1;33m/usr/bin/domain_matching.py --report-location report.txt --report file\033[0m

\033[1;33m/usr/bin/domain_matching.py --domains opendns-top-domains.txt\033[0m

Consume data from certstream and does its magic.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--domains',
                        help='the list of domains to match with (opendns-top-domains.txt)')

    parser.add_argument('--storage-host',
                        help='set the storage host')
    parser.add_argument('-s', '--storage',
                        help='choose the storage type (elasticsearch)')

    parser.add_argument('--report-location', default='report.txt',
                        help='where to save the report to?')
    parser.add_argument('-r', '--report', default='file',
                        help='choose the reporter type')

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

    if args.report and args.report not in SUPPORTED_REPORTERS:
        error = 'Report type \033[1;31m{}\033[0m is not supported. The list of supported reporters includes: {}' \
                .format(args.report, list(SUPPORTED_REPORTERS.keys()))

        logging.error(error)
        # Encounter an unsupported storage type
        sys.exit(1)

    if args.storage and args.storage not in SUPPORTED_STORAGES:
        error = 'Storage type \033[1;31m{}\033[0m is not supported. The list of supported storages includes: {}' \
                .format(args.storage, list(SUPPORTED_STORAGES.keys()))

        logging.error(error)
        # Encounter an unsupported storage type
        sys.exit(1)

    analysers = init_analysers(domains_file=args.domains,
                               include_tld=True,
                               matching_option=DomainMatchingOption.ORDER_MATCH)

    reporter = SUPPORTED_REPORTERS[args.report](args.report_location) if args.report else None
    storage = SUPPORTED_STORAGES[args.storage](args.storage_host) if args.storage else None

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
