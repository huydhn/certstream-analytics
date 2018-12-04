'''
Verify the domain against the list of most popular domains from OpenDNS
(https://github.com/opendns/public-domain-lists). Let's see how useful
it is to prevent phishing domains.
'''
from enum import Enum

import re
import enchant
import tldextract
import wordsegment
from nostril import nonsense
import ahocorasick
import idna

from .base import Analyser

# Take a histogram here and find out the suitable value for this
BULK_DOMAIN_THRESHOLD = 15


# pylint: disable=too-few-public-methods
class AhoCorasickDomainMatching(Analyser):
    '''
    The domain and its SAN will be compared against the list of domains, for
    example, the most popular domains from OpenDNS.
    '''
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
        '''
        Use Aho-Corasick to find the matching domain so we construct its Trie
        here. Thought: How the f**k is com.com in the list?
        '''
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
        '''
        Use Aho-Corasick to find the matching domain. Check the time complexity
        of this function later.

        Tricky situation #1: When the string (domain) in the Trie is too short,
        it could match many domains, for example, g.co or t.co.  So they need
        to be ignored somehow.  Looking at the histogram of the length of all
        domains in the list, there are only less than 100 domains with the
        length of 2 or less.  So we choose to ignore those.  Also, we will
        prefer longer match than a shorter one for now.
        '''
        if 'analysers' not in record:
            record['analysers'] = []

        results = {}
        # Check the domain and all its SAN
        for domain in record['all_domains']:
            # Remove wildcard
            domain = re.sub('^\*\.', '', domain)

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


class WordSegmentation(Analyser):
    '''
    Perform word segmentation of all the SAN domains as an attempt to make sense
    of their names. For example, both arch.mappleonline.com and apple-verifyupdate.serveftp.com
    domains have 'apple' inside but only the second one is an actual Apple phishing
    page. Intuitively, a good word segmentation algorithm will return:

      - arch + mapple + online + com
      - apple + verify + update + serve + ftp + com

    Thus, it's much easier to spot the second phishing domain.

    Implementation-wise, there are several existing packages around to do this, for
    example:

      - https://github.com/grantjenks/python-wordsegment
      - https://github.com/keredson/wordninja

    Let's see what they can do, take it away!
    '''
    # Some common stop words that are in the list of most popular domains
    STOPWORDS = {
        'app': 1,
        'inc': 1,
        'box': 1,
        'health': 1,
        'home': 1,
        'space': 1,
        'cars': 1,
        'nature': 1,
    }

    def __init__(self):
        '''
        Just load the wordsegment package, whatever it is.
        '''
        wordsegment.load()

    def run(self, record):
        '''
        Apply word segment to all the SAN domain names. Let's see if it makes
        any sense.
        '''
        if 'analysers' not in record:
            record['analysers'] = []

        results = {}
        # Check the domain and all its SAN
        for domain in record['all_domains']:
            # Remove wildcard
            domain = re.sub('^\*\.', '', domain)

            # The TLD will be stripped off cause it does not contribute anything here
            ext = tldextract.extract(domain)

            words = []
            # We choose to segment the TLD here as well, for example, .co.uk
            # will become ['co', 'uk']. Let see if this works out.
            for part in ext[:]:
                for token in part.split('.'):
                    words.extend([w for w in wordsegment.segment(token) if w not in WordSegmentation.STOPWORDS])

            results[domain] = words

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

        return record


class DomainMatchingOption(Enum):
    '''
    Control how strict we want to do our matching.
    '''
    # For example applefake.it will match with apple.com case ['apple'] is
    # a subset of ['apple', 'fake']
    SUBSET_MATCH = 0

    # Similar but use in instead of issubset so that the order is preserved
    ORDER_MATCH = 1


class DomainMatching(Analyser):
    '''
    This is the first example of the new group of meta analysers which are used
    to combine the result of other analysers.
    '''
    def __init__(self, include_tld=True, option=DomainMatchingOption.ORDER_MATCH):
        '''
        Just load the wordsegment package, whatever it is.
        '''
        wordsegment.load()

        # Save the matching option here so we can refer to it later
        self.include_tld = include_tld

        self.option = {
            DomainMatchingOption.SUBSET_MATCH: set,
            DomainMatchingOption.ORDER_MATCH: list,
        }[option]

    def run(self, record):
        '''
        Note that a meta-analyser will need to run after other analysers have
        finished so that their outputs are available.
        '''
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

        return record

    def _match(self, ahocorasick_output, segmentation_output):
        '''
        Use internally by the run function to combine AhoCorasick and WordSegmentation
        results.
        '''
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


class BulkDomainMarker(Analyser):
    '''
    Mark the record that has tons of SAN domains in it. Most of the time, they are
    completely unrelated domains and probably the result of some bulk registration
    process. Benign or not, they are still suspicious and probably spam. We can also
    verify the similarity among these domains. A lower similarity score means these
    domains are totally unrelated.
    '''
    def __init__(self, threshold=BULK_DOMAIN_THRESHOLD):
        '''
        Set the threshold to mark the record as a bulk record.
        '''
        self.threshold = threshold

    def run(self, record):
        '''
        See if the record is a bulk record. We will just use the threshold as
        the indicator for now. So if a record has more SAN names than the
        threshold, it is a bulk record.
        '''
        if 'analysers' not in record:
            record['analysers'] = []

        is_bulked = True if len(record['all_domains']) >= self.threshold else False

        record['analysers'].append({
            'analyser': type(self).__name__,
            'output': is_bulked,
        })

        return record


class IDNADecoder(Analyser):
    '''
    Decode all domains in IDNA format.
    '''
    def run(self, record):
        '''
        Check if a domain in the list is in IDNA format and convert it back to
        Unicode.
        '''
        decoded = []

        for domain in record['all_domains']:
            try:
                if re.match('^\*\.', domain):
                    # Remove wildcard domain
                    domain = re.sub('^\*\.', '', domain)
                    domain = idna.decode(domain)
                    domain = '*.{}'.format(domain)
                else:
                    domain = idna.decode(domain)

            except idna.core.InvalidCodepoint:
                # Fail to decode the domain, just keep it as it is for now
                pass
            except UnicodeError:
                pass

            decoded.append(domain)

        record['all_domains'] = decoded
        return record


class FeaturesGenerator(Analyser):
    '''
    Generate features to detect outliers in the stream. In our case, the outliers is
    the 'suspicious' phishing domains.
    '''
    NOSTRIL_LENGTH_LIMIT = 6

    def __init__(self):
        '''
        '''
        self.logos = enchant.Dict('en_US')

    # pylint: disable=invalid-name
    def run(self, record):
        '''
        The list of features will be:
        - The number of domain parts, for example, www.google.com is 3.
        - The overall length in characters.
        - The length of the longest domain part.
        - The length of the TLD, e.g. .online or .download is longer than .com.
        - The randomness level of the domain.
        '''
        if 'analysers' not in record:
            record['analysers'] = []

        x_samples = []
        Y_samples = []

        for analyser in record['analysers']:
            if analyser['analyser'] != 'WordSegmentation':
                continue

            for domain, segments in analyser['output'].items():
                # Remove wildcard domain
                domain = re.sub('^\*\.', '', domain)

                parts = domain.split('.')

                x = []
                # Compute the number of domain parts
                x.append(len(parts))

                # Compute the length of the whole domain
                x.append(len(domain))

                longest = ''
                # Compute the length of the longest domain parts
                for part in parts:
                    if len(part) > len(longest):
                        longest = part

                x.append(len(longest))

                # Compute the length of the TLD
                x.append(len(parts[-1]))

                randomness_count = 0
                # The nostril package which we are using to detect non-sense words
                # in the domain only returns a boolean verdict so may be we need to
                # think of how we want to quantify this
                for w in segments:
                    try:
                        if len(w) >= FeaturesGenerator.NOSTRIL_LENGTH_LIMIT and nonsense(w):
                            randomness_count += 1
                    except ValueError:
                        continue

                x.append(randomness_count / len(segments))

                x_samples.append(x)
                Y_samples.append(True if 'usual_suspect' in record else False)

            break

        record['analysers'].append({
            'analyser': type(self).__name__,
            'output': x_samples,
        })

        return record
