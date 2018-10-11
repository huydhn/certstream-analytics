Certstream + Analytics
----------------------

[![Build Status](https://travis-ci.org/huydhn/certstream-analytics.svg?branch=master)](https://travis-ci.org/huydhn/certstream-analytics)
[![codecov.io](https://codecov.io/gh/huydhn/certstream-analytics/master.svg)](http://codecov.io/gh/huydhn/certstream-analytics?branch=master)


Installation
------------

The package can be installed from
[PyPI](https://pypi.org/project/certstream-analytics)

```
pip install certstream-analytics
```

Usage
-----

```python
import time

from certstream_analytics.analysers import Debugger
from certstream_analytics.transformers import CertstreamTransformer
from certstream_analytics.storages import ElasticsearchStorage
from certstream_analytics.stream import CertstreamAnalytics

done = False

# This will just print out the record for debugging purpose
debugger = Debugger()

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
                               analyser=debugger)
# The consumer is run in another thread so this function is non-blocking
consumer.start()

while not done:
    time.sleep(1)

consumer.stop()
```
