'''
Apply the local outlier factor method to separate our outliers.
'''
import json
import sys
import numpy as np

from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import scale


def main():
    '''
    The procedure contains two simple steps:
        - Scale the data to the standard distribution with mean 0 and unit variance.
          This might be too simplistic.
        - Apply the local outlier factor.  The contamination level is set manually.

    This method does not seem to work in our case cause I suspect it treats groups
    of several outliers as clusters.
    '''
    domains = []
    raw = []

    with open(sys.argv[1]) as fhandle:
        for line in fhandle:
            record = json.loads(line.strip())

            for analyser in record['analysers']:
                if analyser['analyser'] == 'FeaturesGenerator':
                    raw.extend(analyser['output'])

                if analyser['analyser'] == 'WordSegmentation':
                    domains.extend(analyser['output'].keys())

            if len(raw) != len(domains):
                print(record)
                sys.exit(0)

    x_samples = scale(np.array(raw))

    # Need to check the appropriate value for n_neighbors
    engine = LocalOutlierFactor(contamination=0.015)
    y_samples = engine.fit_predict(x_samples)

    for index, y_sample in enumerate(y_samples):
        if y_sample == -1:
            print(domains[index])


if __name__ == '__main__':
    main()
