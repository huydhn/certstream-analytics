'''
Verify the domain against the list of most popular domains from OpenDNS
(https://github.com/opendns/public-domain-lists). Let's see how useful
it is to prevent phishing domains.
'''
from .base import Analyser


# pylint: disable=no-init,too-few-public-methods
class CommonDomainMatching(Analyser):
    '''
    The domain and its SAN will be compared against the list of domains, for
    exaple, the most popular domains from OpenDNS.
    '''
    def __init__(self, domains):
        '''
        '''
        self.domains = domains if domains else []

    def run(self, record):
        '''
        TODO: Find a good, O(log(n)) or less, solution to this problem.
        '''
        if not self.domains:
            return None

        for legit_domain in self.domains:
            for domain in record['all_domains']:
                if legit_domain in domain:
                    return domain

        return None
