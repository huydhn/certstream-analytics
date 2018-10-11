#!/usr/bin/env python3.6
'''
A simple utility to query certstream and store the result.
'''
import argparse
import logging
import signal
import sys
import time

from certstream_analytics.analysers import Debugger
from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.stream import CertstreamAnalytics

DONE = False

SUPPORTED_STORAGE_TYPES = {
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


def run():
    '''
    A simple utility to query certstream and store the result.
    '''
    epilog = '''
examples:
\033[1;33m/usr/bin/certstream_consumer.py -h my-elasticsearch-host:9200 -s elasticsearch\033[0m

Consume data from certstream and store it in Elasticsearch.
'''
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--host', default='localhost:9200',
                        help='Choose the storage host.')
    parser.add_argument('-s', '--storage', default='elasticsearch',
                        help='Choose the storage type, for example, elasticsearch')

    try:
        args = parser.parse_args()
    # pylint: disable=broad-except
    except Exception as error:
        logging.error(error)
        # some errors occur when parsing the arguments, show the usage
        parser.print_help()
        # then quit
        sys.exit(1)

    debugger = Debugger()
    transformer = CertstreamTransformer()

    if args.storage not in SUPPORTED_STORAGE_TYPES.keys():
        error = 'Storage type \033[1;31m{}\033[0m is not supported. The list of supported storages includes: {}' \
                .format(args.storage, list(SUPPORTED_STORAGE_TYPES.keys()))

        logging.error(error)
        # Encounter an unsupported storage type
        sys.exit(1)

    storage = SUPPORTED_STORAGE_TYPES[args.storage](args.host)
    engine = CertstreamAnalytics(transformer=transformer,
                                 storage=storage,
                                 analyser=debugger)
    engine.start()

    while not DONE:
        time.sleep(1)

    engine.stop()


if __name__ == '__main__':
    # Make sure that we can exit gracefully
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    run()
