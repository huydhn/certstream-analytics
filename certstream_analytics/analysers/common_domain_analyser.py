'''
Verify the domain against the list of most popular domains from OpenDNS
(https://github.com/opendns/public-domain-lists). Let's see how useful
it is to prevent phishing domains.
'''
import tldextract
import wordsegment
import ahocorasick

from .base import Analyser


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
        'www',
        'web',
    }

    def __init__(self, domains):
        '''
        Use Aho-Corasick to find the matching domain so we construct its Trie
        here. Thought: How the f**k is com.com in the list?
        '''
        self.automaton = ahocorasick.Automaton()

        for index, domain in enumerate(domains):
            # Processing only the domain part so all sub-domains or TLDs will
            # be ignored, for example:
            #   - www.google.com becomes google
            #   - www.google.co.uk becomes google
            #   - del.icio.us becomes icio
            ext = tldextract.extract(domain)

            if ext.domain in AhoCorasickDomainMatching.EXCLUDED_DOMAINS:
                continue

            self.automaton.add_word(ext.domain, (index, ext.domain))

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
            # Similar to all domains in the list, the TLD will be stripped off
            ext = tldextract.extract(domain)
            # The match will be a tuple in the following format: (5, (0, 'google'))
            matches = [m[1][1] for m in self.automaton.iter('.'.join(ext[:2]))
                       if len(m[1][1]) >= AhoCorasickDomainMatching.MIN_MATCHING_LENGTH]

            if matches:
                matches.sort(key=len)
                # We only keep the the longest match of the first matching domain
                # for now
                results[domain] = [matches[-1]]
                break

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

        return record


# pylint: disable=too-few-public-methods
class WordSegmentationAnalyser(Analyser):
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
            # The TLD will be stripped off cause it does not contribute anything here
            ext = tldextract.extract(domain)

            words = []
            for part in ext[:2]:
                for token in part.split('.'):
                    words.extend(wordsegment.segment(token))

            results[domain] = words

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

        return record
