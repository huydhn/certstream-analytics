'''
Generate features for outlier detection.
'''

import json
import sys

from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import IDNADecoder
from certstream_analytics.analysers import FeaturesGenerator

def main(max_count=None):
    '''
    The record is assumed to be stored in a JSON file passed in as the first
    parameter of the script.
    '''
    segmenter = WordSegmentation()
    decoder = IDNADecoder()
    generator = FeaturesGenerator()

    with open(sys.argv[1]) as fhandle:
        count = 0

        for line in fhandle:
            try:
                record = json.loads(line.strip())
            except json.decoder.JSONDecodeError:
                continue

            record = decoder.run(record)
            record = segmenter.run(record)
            record = generator.run(record)

            print(json.dumps(record))
            count += 1

            if max_count and count > max_count:
                break


if __name__ == '__main__':
    main()
