'''
Generate features for outlier detection.
'''

import json
import sys

from certstream_analytics.analysers import FeaturesGenerator

def main():
    '''
    The record is assumed to be stored in a JSON file passed in as the first
    parameter of the script.
    '''
    generator = FeaturesGenerator()

    with open(sys.argv[1]) as fhandle:
        for line in fhandle:
            record = json.loads(line.strip())
            record = generator.run(record)

            print(json.dumps(record))


if __name__ == '__main__':
    main()
