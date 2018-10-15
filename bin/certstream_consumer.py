#!/usr/bin/env python3
'''
A simple utility to query certstream and store the result.
'''
import argparse
import logging
import signal
import sys
import time

from certstream_analytics.analysers import AhoCorasickDomainMatching, Debugger
from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.reporter import FileReporter
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.stream import CertstreamAnalytics

DONE = False


# pylint: disable=unused-argument
def exit_gracefully(signum, stack):
    '''
    Just to be nice.
    '''
    # pylint: disable=global-statement
    global DONE
    DONE = True


def init_ahocorasick_analyser(params):
    '''
    Initialize the AhoCorasick analyser here cause this could not be fitted
    into a lambda. We only take the first parameter as the path to the list
    of domains to be compared against.
    '''
    with open(params[0]) as fhandle:
        domains = [line.rstrip() for line in fhandle]

    return AhoCorasickDomainMatching(domains=domains)


SUPPORTED_ANALYSERS = {
    'debugger': lambda params: Debugger(),
    'ahocorasick': init_ahocorasick_analyser,
}

SUPPORTED_REPORTERS = {
    'file': lambda location: FileReporter(path=location)
}

SUPPORTED_STORAGES = {
    'elasticsearch': lambda host: ElasticsearchStorage(hosts=[host])
}


def run():
    '''
    A simple utility to query certstream and store the result.
    '''
    epilog = '''
examples:
\033[1;33m/usr/bin/certstream_consumer.py --storage-location elasticsearch-host:9200 -s elasticsearch\033[0m

\033[1;33m/usr/bin/certstream_consumer.py --report-location report.txt\033[0m

\033[1;33m/usr/bin/certstream_consumer.py --analyser ahocorasick --analyser-param opendns-top-domains.txt\033[0m

Consume data from certstream and store it in Elasticsearch.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--analyser-param', nargs='+',
                        help='A parameter used by the analyser. This parameter can be specified multiple times.')
    parser.add_argument('-a', '--analyser', default='ahocorasick',
                        help='Choose the type of analyser to use, for example, ahocorasick')

    parser.add_argument('--storage-host', default='localhost:9200',
                        help='Choose the storage host.')
    parser.add_argument('-s', '--storage', default='elasticsearch',
                        help='Choose the storage type, for example, elasticsearch')

    parser.add_argument('--report-location',
                        help='Choose the location of the report, for example, a file path.')
    parser.add_argument('-r', '--report', default='file',
                        help='Choose the reporter, for example, file')

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

    if args.analyser and args.analyser not in SUPPORTED_ANALYSERS:
        error = 'Analyser type \033[1;31m{}\033[0m is not supported. The list of supported analyserss includes: {}' \
                .format(args.analyser, list(SUPPORTED_ANALYSERS.keys()))

        logging.error(error)
        # Encounter an unsupported storage type
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

    if args.analyser:
        analyser = SUPPORTED_ANALYSERS[args.analyser](args.analyser_param)

    if args.report:
        reporter = SUPPORTED_REPORTERS[args.report](args.report_location)

    if args.storage:
        storage = SUPPORTED_STORAGES[args.storage](args.storage_host)

    engine = CertstreamAnalytics(transformer=transformer,
                                 storage=storage,
                                 analyser=analyser,
                                 reporter=reporter)
    engine.start()

    while not DONE:
        time.sleep(1)

    engine.stop()


if __name__ == '__main__':
    # Make sure that we can exit gracefully
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    run()
