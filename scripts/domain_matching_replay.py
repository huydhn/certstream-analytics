#!/usr/bin/env python3
'''
Replay a stream of records from certstream to test the domain matching pipeline.
It's similar to the domain_matching.py script without the connection to certstream
to get live data.
'''
import argparse
import json
import logging
import sys

from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import DomainMatching, DomainMatchingOption
from certstream_analytics.reporters import FileReporter
from certstream_analytics.storages import ElasticsearchStorage


SUPPORTED_REPORTERS = {
    'file': lambda location: FileReporter(path=location)
}

SUPPORTED_STORAGES = {
    'elasticsearch': lambda host: ElasticsearchStorage(hosts=[host])
}


def init_analysers(domains_file, include_tld, matching_option):
    '''
    Initialize all the analysers for matching domains. The list includes:

    - AhoCorasick.
    - Word segmentation.
    - Meta domain matching.
    '''
    with open(domains_file) as fhandle:
        domains = [line.rstrip() for line in fhandle]

    # Initialize all analysers. Note that their order is important cause they
    # will be executed in that order
    return [
        AhoCorasickDomainMatching(domains=domains),
        WordSegmentation(),
        DomainMatching(include_tld=include_tld, option=matching_option),
    ]


def run():
    '''
    A simple utility to replay certstream and match the records to a list of
    known domains from OpenDNS.
    '''
    epilog = '''
examples:
\033[1;33m/usr/bin/certstream_consumer.py --replay certstream.txt\033[0m

\033[1;33m/usr/bin/certstream_consumer.py --storage-host elasticsearch:9200 --storage elasticsearch\033[0m

\033[1;33m/usr/bin/certstream_consumer.py --report-location report.txt --report file\033[0m

\033[1;33m/usr/bin/certstream_consumer.py --domains opendns-top-domains.txt\033[0m

Consume data from certstream and does its magic.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--replay',
                        help='the list of records from certstream (one per line)')
    parser.add_argument('--domains',
                        help='the list of domains to match with (opendns-top-domains.txt)')

    parser.add_argument('--storage-host', default='localhost:9200',
                        help='set the storage host')
    parser.add_argument('-s', '--storage', default='elasticsearch',
                        help='choose the storage type (elasticsearch)')

    parser.add_argument('--report-location',
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

    if args.report:
        reporter = SUPPORTED_REPORTERS[args.report](args.report_location)

    if args.storage:
        storage = SUPPORTED_STORAGES[args.storage](args.storage_host)

    with open(args.replay) as fhandler:
        for raw in fhandler:
            try:
                record = json.loads(raw)
            except json.decoder.JSONDecodeError:
                continue

            storage.save(record)

            for analyser in analysers:
                # Run something here
                record = analyser.run(record)

            reporter.publish(record)

if __name__ == '__main__':
    run()
