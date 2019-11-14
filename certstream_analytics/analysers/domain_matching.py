"""
Verify the domain against the list of most popular domains from OpenDNS
(https://github.com/opendns/public-domain-lists). Let's see how useful
it is to prevent phishing domains.
"""
from enum import Enum

import json
import logging
import re
import tldextract
import ahocorasick
import wordsegment

from .base import Analyser
from .common_domain_analyser import BulkDomainMarker
from .common_domain_analyser import WordSegmentation


# pylint: disable=too-few-public-methods
class AhoCorasickDomainMatching(Analyser):
    """
    The domain and its SAN will be compared against the list of domains, for
    example, the most popular domains from OpenDNS.
    """
    # Get this number from the histogram of the length of all top domains
    MIN_MATCHING_LENGTH = 3

    # Some domains that don't work too well with tldextract and generate too
    # many FPs
    EXCLUDED_DOMAINS = {
        'www': 1,
        'web': 1,
    }

    # Some common domain parts that cause too many FP
    IGNORED_PARTS = r'^(autodiscover\.|cpanel\.)'

    def __init__(self, domains):
        """
        Use Aho-Corasick to find the matching domain so we construct its Trie
        here. Thought: How the f**k is com.com in the list?
        """
        self.automaton = ahocorasick.Automaton()
        self.domains = {}

        for index, domain in enumerate(domains):
            # Processing only the domain part.  All sub-domains or TLDs will
            # be ignored, for example:
            #   - www.google.com becomes google
            #   - www.google.co.uk becomes google
            #   - del.icio.us becomes icio
            ext = tldextract.extract(domain)

            if ext.domain in AhoCorasickDomainMatching.EXCLUDED_DOMAINS:
                continue

            self.automaton.add_word(ext.domain, (index, ext.domain))
            self.domains[ext.domain] = domain

        self.automaton.make_automaton()

    def run(self, record):
        """
        Use Aho-Corasick to find the matching domain. Check the time complexity
        of this function later.

        Tricky situation #1: When the string (domain) in the Trie is too short,
        it could match many domains, for example, g.co or t.co.  So they need
        to be ignored somehow.  Looking at the histogram of the length of all
        domains in the list, there are only less than 100 domains with the
        length of 2 or less.  So we choose to ignore those.  Also, we will
        prefer longer match than a shorter one for now.
        """
        if 'analysers' not in record:
            record['analysers'] = []

        results = {}
        # Check the domain and all its SAN
        for domain in record['all_domains']:
            # Remove wildcard
            domain = re.sub(r'^\*\.', '', domain)

            # Remove some FP-prone parts
            domain = re.sub(AhoCorasickDomainMatching.IGNORED_PARTS, '', domain)

            # Similar to all domains in the list, the TLD will be stripped off
            ext = tldextract.extract(domain)
            # The match will be a tuple in the following format: (5, (0, 'google'))
            matches = [m[1][1] for m in self.automaton.iter('.'.join(ext[:2]))
                       if len(m[1][1]) >= AhoCorasickDomainMatching.MIN_MATCHING_LENGTH]

            if matches:
                matches.sort(key=len)

                match = matches[-1]
                # We only keep the the longest match of the first matching domain
                # for now
                results[domain] = [self.domains[match]] if match in self.domains else match
                break

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

        return record


class DomainMatchingOption(Enum):
    """
    Control how strict we want to do our matching.
    """
    # For example applefake.it will match with apple.com case ['apple'] is
    # a subset of ['apple', 'fake']
    SUBSET_MATCH = 0

    # Similar but use in instead of issubset so that the order is preserved
    ORDER_MATCH = 1


class DomainMatching(Analyser):
    """
    This is the first example of the new group of meta analysers which are used
    to combine the result of other analysers.
    """
    def __init__(self, include_tld=True, option=DomainMatchingOption.ORDER_MATCH):
        """
        Just load the wordsegment package, whatever it is.
        """
        wordsegment.load()

        # Save the matching option here so we can refer to it later
        self.include_tld = include_tld

        self.option = {
            DomainMatchingOption.SUBSET_MATCH: set,
            DomainMatchingOption.ORDER_MATCH: list,
        }[option]

    def run(self, record):
        """
        Note that a meta-analyser will need to run after other analysers have
        finished so that their outputs are available.
        """
        if 'analysers' not in record:
            return record

        analysers = {
            AhoCorasickDomainMatching.__name__: {},
            WordSegmentation.__name__: {},
            BulkDomainMarker.__name__: {},
        }

        for analyser in record['analysers']:
            name = analyser['analyser']

            if name not in analysers:
                continue

            if name == BulkDomainMarker.__name__ and analyser['output']:
                # Skip bulk record and deal with it later, with such large
                # number of SAN name, it's bound to be a match
                continue

            analysers[name] = analyser['output']

        # Check that all outputs are there before continuing
        if not analysers[AhoCorasickDomainMatching.__name__] or not analysers[WordSegmentation.__name__]:
            return record

        results = self._match(analysers[AhoCorasickDomainMatching.__name__],
                              analysers[WordSegmentation.__name__])

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

            # DEBUG
            logging.info(json.dumps(record))

        return record

    def _match(self, ahocorasick_output, segmentation_output):
        """
        Use internally by the run function to combine AhoCorasick and WordSegmentation
        results.
        """
        results = {}
        # Check all the matching domains reported by AhoCorasick analyser
        for match, domains in ahocorasick_output.items():
            # The result of AhoCorasick matcher is a list of matching domains, for example,
            #
            #   {
            #       'analyser': 'AhoCorasickDomainMatching',
            #       'output': {
            #           'login-appleid.apple.com.managesuppport.co': ['apple.com', 'support.com'],
            #       },
            #   },
            #
            if match not in segmentation_output:
                continue

            phish = self.option(segmentation_output[match])
            match_ext = tldextract.extract(match)

            for domain in domains:
                ext = tldextract.extract(domain)

                # This record is from a legitimate source, for example, agrosupport.zendesk.com
                # will match with zendesk.com. In our case, we don't really care about this so
                # it will be ignored and not reported as a match.
                if ext[1:] == match_ext[1:]:
                    continue

                tmp = []
                # Intuitively, it will be more accurate if we choose to include the TLD here.
                # For example, if both 'apple' and 'com' appear in the matching domain, it's
                # very likely that something phishing is going on here. On the other hand,
                # if only 'apple' occurs, we are not so sure and it's better left for more
                # advance analysers to have their says in that
                for part in ext[:] if self.include_tld else ext[:2]:
                    for token in part.split('.'):
                        tmp.extend(wordsegment.segment(token))

                legit = self.option(tmp)

                if (isinstance(phish, set) and legit.issubset(phish)) or \
                   (isinstance(phish, list) and '.{}'.format('.'.join(legit)) in '.'.join(phish)):
                    # Found a possible phishing domain
                    if match not in results:
                        results[match] = []

                    results[match].append(domain)

        return results
