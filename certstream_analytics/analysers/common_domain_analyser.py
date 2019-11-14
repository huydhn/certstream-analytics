"""
The list of basic analysers includes:
    - WordSegmentation
    - IDNADecoder
    - HomoglyphsDecoder
    - FeaturesGenerator (generate various features for further downstream processing)
    - BulkDomainMarker
"""
import re
import tldextract
import wordsegment
from nostril import nonsense
import idna
from confusable_homoglyphs import confusables

from .base import Analyser


# pylint: disable=too-few-public-methods
class WordSegmentation(Analyser):
    """
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
    """
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
        """
        Just load the wordsegment package, whatever it is.
        """
        wordsegment.load()

    def run(self, record):
        """
        Apply word segment to all the SAN domain names. Let's see if it makes
        any sense.
        """
        if 'analysers' not in record:
            record['analysers'] = []

        results = {}
        # Check the domain and all its SAN
        for domain in record['all_domains']:
            # Remove wild card
            domain = re.sub(r'^\*\.', '', domain)

            # The TLD will be stripped off cause it does not contribute anything here
            ext = tldextract.extract(domain)

            words = []
            # We choose to segment the TLD here as well, for example, .co.uk
            # will become ['co', 'uk']. Let see if this works out.
            for part in ext[:]:
                for token in part.split('.'):
                    segmented = [w for w in wordsegment.segment(token) if w not in WordSegmentation.STOPWORDS]

                    if segmented:
                        words.extend(segmented)
                    elif token:
                        # For some IDNA domain like xn--wgbfq3d.xn--ngbc5azd, the segmentation
                        # won't work and an empty array is returned. So we choose to just keep
                        # the original token
                        words.append(token)

            results[domain] = words

        if results:
            record['analysers'].append({
                'analyser': type(self).__name__,
                'output': results,
            })

        return record


class BulkDomainMarker(Analyser):
    """
    Mark the record that has tons of SAN domains in it. Most of the time, they are
    completely unrelated domains and probably the result of some bulk registration
    process. Benign or not, they are still suspicious and probably spam. We can also
    verify the similarity among these domains. A lower similarity score means these
    domains are totally unrelated.
    """
    # Take a histogram here and find out the suitable value for this
    THRESHOLD = 15

    def __init__(self, threshold=THRESHOLD):
        """
        Set the threshold to mark the record as a bulk record.
        """
        self.threshold = threshold

    def run(self, record):
        """
        See if the record is a bulk record. We will just use the threshold as
        the indicator for now. So if a record has more SAN names than the
        threshold, it is a bulk record.
        """
        if 'analysers' not in record:
            record['analysers'] = []

        is_bulked = len(record['all_domains']) >= self.threshold

        record['analysers'].append({
            'analyser': type(self).__name__,
            'output': is_bulked,
        })

        return record


class IDNADecoder(Analyser):
    """
    Decode all domains in IDNA format.
    """
    def run(self, record):
        """
        Check if a domain in the list is in IDNA format and convert it back to
        Unicode.
        """
        decoded = []

        for domain in record['all_domains']:
            wildcard = False

            try:
                if re.match(r'^\*\.', domain):
                    wildcard = True
                    # Remove wildcard cause it interfere with the IDNA module
                    # and we'll put it back later
                    domain = re.sub(r'^\*\.', '', domain)

                domain = idna.decode(domain)

            except idna.core.InvalidCodepoint:
                # Fail to decode the domain, just keep it as it is for now
                pass
            except UnicodeError:
                pass
            finally:
                if wildcard:
                    domain = '*.{}'.format(domain)

            decoded.append(domain)

        record['all_domains'] = decoded
        return record


class HomoglyphsDecoder(Analyser):
    """
    Smartly convert domains whose names include some suspicious homoglyphs to
    ASCII.  This will probably need to be right done after IDNA conversion and
    before other analysers so that they can get benefits from it.
    """
    def __init__(self, greedy=False):
        """
        We rely on the confusable-homoglyphs at https://github.com/vhf/confusable_homoglyphs
        to do its magic.

        If the greedy flag is set, all alternative domains will be returned.  Otherwise, only
        the first one will be available.
        """
        self.greedy = greedy

    @staticmethod
    def is_latin(alt):
        """
        Check if a string is in Latin cause, in our specific case, we will
        only care about Latin characters
        """
        lower_s = range(ord('a'), ord('z') + 1)
        upper_s = range(ord('A'), ord('Z') + 1)

        # We need to check the length of the homoglyph here cause
        # confusable_homoglyphs library nicely returns multi-character
        # match as well, for example, 'rn' has an alternative of 'm'
        for alt_c in alt:
            if ord(alt_c) not in lower_s and ord(alt_c) not in upper_s:
                return False

        return True

    def run(self, record):
        """
        Using the confusable-homoglyphs, we are going to generate all alternatives ASCII
        names of a domain.  It's a bit of a brute force though.
        """
        decoded = []

        for domain in record['all_domains']:
            wildcard = False

            if re.match(r'^\*\.', domain):
                wildcard = True
                # Remove wild card to simplify the domain name a bit and we'll put it back later
                domain = re.sub(r'^\*\.', '', domain)

            hg_map = {hg['character']: hg for hg in confusables.is_confusable(domain, greedy=True)}
            decoded_domain_c = []

            for domain_c in domain:
                # Confusable homoglyphs could not find any homoglyphs for this character
                # so we decide to keep the original character as it is
                if domain_c not in hg_map:
                    decoded_domain_c.append([domain_c])
                    continue

                found = []
                hglyph = hg_map[domain_c]

                if hglyph['alias'] == 'LATIN':
                    # The character is Latin, we don't need to do anything here
                    found.append(hglyph['character'])

                for alt in hglyph['homoglyphs']:
                    if HomoglyphsDecoder.is_latin(alt['c']):
                        found.append(alt['c'].lower())

                # If nothing is found, we keep the original character
                if not found:
                    found.append(hglyph['character'])

                decoded_domain_c.append(found)

            for alt in self._generate_alternatives(decoded_domain_c):
                if wildcard:
                    alt = '*.{}'.format(alt)

                decoded.append(alt)

                if not self.greedy:
                    break

        record['all_domains'] = decoded
        return record

    def _generate_alternatives(self, alt_characters, index=0, current=''):
        """
        Generate all alternative ASCII names of a domain using the list of all
        alternative characters.
        """
        if index == len(alt_characters):
            yield current

        else:
            for alt_c in alt_characters[index]:
                yield from self._generate_alternatives(alt_characters,
                                                       index + 1,
                                                       current + alt_c)


class FeaturesGenerator(Analyser):
    """
    Generate features to detect outliers in the stream. In our case, the outliers is
    the 'suspicious' phishing domains.
    """
    NOSTRIL_LENGTH_LIMIT = 6

    # pylint: disable=invalid-name
    def run(self, record):
        """
        The list of features will be:
        - The number of domain parts, for example, www.google.com is 3.
        - The overall length in characters.
        - The length of the longest domain part.
        - The length of the TLD, e.g. .online or .download is longer than .com.
        - The randomness level of the domain.
        """
        if 'analysers' not in record:
            record['analysers'] = []

        x_samples = []
        Y_samples = []

        for analyser in record['analysers']:
            if analyser['analyser'] != 'WordSegmentation':
                continue

            for domain, segments in analyser['output'].items():
                # Remove wildcard domain
                domain = re.sub(r'^\*\.', '', domain)

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
                Y_samples.append('usual_suspect' in record)

            break

        record['analysers'].append({
            'analyser': type(self).__name__,
            'output': x_samples,
        })

        return record
