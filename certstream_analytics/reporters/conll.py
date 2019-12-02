"""
Save word segmentation output in CoNLL format
https://universaldependencies.org/format.html
"""
from nltk.stem import PorterStemmer

from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.reporters import Reporter


class CoNLL(Reporter):
    """
    Save the word segmentation output in CoNLL format
    """
    def __init__(self, path):
        """
        Note that an exception will be raised if the path is not valid or writable.
        """
        self.fhandle = open(path, 'a')

    def __del__(self):
        self.fhandle.close()

    def publish(self, report):
        """
        Only save word segmentation output for annotation
        """
        if not report:
            return

        # To perform word stemming and get the word root
        stemmer = PorterStemmer()

        for analyser in report['analysers']:
            if analyser['analyser'] != WordSegmentation.__name__:
                continue

            for domain, segments in analyser['output'].items():
                # Save the domain as metadata
                print(f'# text = {domain}', file=self.fhandle)

                for index, word in enumerate(segments):
                    if word == WordSegmentation.SEPARATOR:
                        upos = WordSegmentation.SEPARATOR
                        word = '.'
                    else:
                        upos = '_'

                    # Each domain is a sentence and its words are the tokens
                    print(f'{index+1}\t{word}\t{stemmer.stem(word)}\t{upos}', file=self.fhandle)

                print(f'', file=self.fhandle)
