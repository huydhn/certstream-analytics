# Certstream + Analytics

[![Build Status](https://travis-ci.org/huydhn/certstream-analytics.svg?branch=master)](https://travis-ci.org/huydhn/certstream-analytics)
[![codecov.io](https://codecov.io/gh/huydhn/certstream-analytics/master.svg)](http://codecov.io/gh/huydhn/certstream-analytics?branch=master)


# Installation

The package can be installed from
[PyPI](https://pypi.org/project/certstream-analytics)

```
pip install certstream-analytics
```

# Usage

```python
import time

from certstream_analytics.analysers import WordSegmentation
from certstream_analytics.analysers import IDNADecoder
from certstream_analytics.analysers import HomoglyphsDecoder

from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.stream import CertstreamAnalytics

done = False

# These analysers will be run in the same order
analyser = [
    IDNADecoder(),
    HomoglyphsDecoder(),
    WordSegmentation(),
]

# The following fields are filtered out and indexed:
# - String: domain
# - List: SAN
# - List: Trust chain
# - Timestamp: Not before
# - Timestamp: Not after
# - Timestamp: Seen
transformer = CertstreamTransformer()

# Indexed the data in Elasticsearch
storage = ElasticsearchStorage(hosts=['localhost:9200'])

consumer = CertstreamAnalytics(transformer=transformer,
                               storage=storage,
                               analyser=analyser)
# The consumer is run in another thread so this function is non-blocking
consumer.start()

while not done:
    time.sleep(1)

consumer.stop()
```

## Most popular domains matching (for Anti-phishing)

A domain and its SAN from Certstream will be compared against a list of
most popular [domains](https://github.com/opendns/public-domain-lists)
(from OpenDNS).  This is a simple check to remove some of the most
obvious phishing domains, for examples, *www.facebook.com.msg40.site*
will match with *facebook* cause *facebook* is in the above list of most
popular domains (I wonder how long it is going to last).

### IDNA decoder
This analyser decode IDNA domain name into Unicode for further processing
downstream.  Normally, it will be the very first analyser to be run.  If
the analyser encounters a malform IDNA domain string, it will keep the
domain as it is.

```python
decoder = IDNADecoder()

# Just an example dummy record
record = {
    'all_domains': [
        'xn--f1ahbgpekke1h.xn--p1ai',
    ]
}

# The domain name will now become 'укрэмпужск.рф'
print(decoder.run(record))
```

### Homoglyphs decoder
There are lots of phishing websites that utilize [homoglyphs](https://en.wikipedia.org/wiki/Homoglyph)
to lure the victims.  Some common examples include 'l' and 'i' or the
Unicode character RHO '𝞀' and 'p'.  The homoglyphs decoder uses the excellent
[confusable_homoglyphs](https://github.com/vhf/confusable_homoglyphs) to
generate all potential alternative domain names in ASCII.

```python
# If the greedy flag is set, all alternative domains will be returned
decoder = HomoglyphsDecoder(greed=False)

# Just an example dummy record
record = {
    'all_domains': [
        # MATHEMATICAL MONOSPACE SMALL P
        '*.𝗉aypal.com',

        # MATHEMATICAL SAN-SERIF BOLD SMALL RHO
        '*.𝗉ay𝞀al.com',
    ]
}

# The domain name will now be converted to '*.paypal.com' with the ASCII
# character p
print(decoder.run(record))
```

### Aho-Corasick

```python
from certstream_analytics.analysers import AhoCorasickDomainMatching
from certstream_analytics.reporter import FileReporter

# Print the list of matching domains
reporter = FileReporter('matching-results.txt')

with open('opendns-top-domains.txt')) as fhandle:
    domains = [line.rstrip() for line in fhandle]

# The list of domains to match against
domain_matching_analyser = AhoCorasickDomainMatching(domains)

consumer = CertstreamAnalytics(transformer=transformer,
                               analyser=domain_matching_analyser,
                               reporter=reporter)

# Need to think about what to do with the matching result
consumer.start()

while not done:
    time.sleep(1)

consumer.stop()
```

### Word segmentation
