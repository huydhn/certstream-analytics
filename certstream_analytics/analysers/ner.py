"""
Perform name entity recognition on the URL to extract brand name.
"""
from typing import Dict

from flair.data import Sentence
from flair.models import SequenceTagger

from .base import Analyser
from .common_domain_analyser import WordSegmentation


# pylint: disable=too-few-public-methods
class BrandRecognition(Analyser):
    """
    For this to work, we will need the output of WordSegmentation analyser to
    tokenize the URL.  Due to the nature of the URL text which is composed of
    few short chunks of tokens at most, we need to train our own model for the
    task.  The current model is implemented and trained using flair library at
    https://github.com/zalandoresearch/flair
    """
    def __init__(self, model_path: str):
        """
        After training the model, we just need to load and use it here.
        """
        self.model = SequenceTagger.load(model_path)

    def run(self, record: Dict) -> Dict:
        """
        Convert the record we have into Sentences consumable by flair and apply
        the model.
        """
        if 'analysers' not in record:
            record['analysers'] = []

        for analyser in record['analysers']:
            if analyser['analyser'] != WordSegmentation.__name__:
                continue

            results = {}
            for domain, segments in analyser['output'].items():
                sentence = Sentence(
                    ' '.join([token if token != WordSegmentation.SEPARATOR else '.' for token in segments])
                )
                self.model.predict(sentence)
                results[domain] = sentence.to_tagged_string()

            if results:
                record['analysers'].append({
                    'analyser': type(self).__name__,
                    'output': results,
                })

        return record
