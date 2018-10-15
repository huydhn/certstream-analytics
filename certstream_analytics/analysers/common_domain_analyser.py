'''
Verify the domain against the list of most popular domains from OpenDNS
(https://github.com/opendns/public-domain-lists). Let's see how useful
it is to prevent phishing domains.
'''
import json
import logging
import tldextract
import ahocorasick

from .base import Analyser


# pylint: disable=no-init,too-few-public-methods
class AhoCorasickDomainMatching(Analyser):
    '''
    The domain and its SAN will be compared against the list of domains, for
    example, the most popular domains from OpenDNS.
    '''
    # Get this number from the histogram of the length of all top domains
    MIN_MATCHING_LENGTH = 5

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
        use Aho-Corasick to find the matching domain. Check the time complexity
        of this function later.

        Tricky situation #1: When the string (domain) in the Trie is too short,
        it could match many domains, for example, g.co or t.co.  So they need
        to be ignored somehow.  Looking at the histogram of the length of all
        domains in the list, there are only less than 100 domains with the
        length of 2 or less.  So we choose to ignore those.  Also, we will
        prefer longer match than a shorter one for now.
        '''
        logging.info(json.dumps(record))

        # Check the domain and all its SAN
        for domain in record['all_domains']:
            # Similar to all domains in the list, the TLD will be stripped off
            ext = tldextract.extract(domain)
            # The match will be a tuple in the following format: (5, (0, 'google'))
            matches = [m[1][1] for m in self.automaton.iter('.'.join(ext[:2]))
                       if len(m[1][1]) >= AhoCorasickDomainMatching.MIN_MATCHING_LENGTH]

            if matches:
                matches.sort(key=len)
                # and we prefer the longest match for now
                return {'domain': domain, 'match': matches[-1]}

        return {}
