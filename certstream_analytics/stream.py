'''
All hail [certstream](https://github.com/CaliDog/certstream-python)!!

This module consumes the feed of certificates from certstream and does
the heavy lifting.
'''
import sys
import threading
import certstream

from certstream_analytics.analysers import Analyser
from certstream_analytics.reporters import Reporter
from certstream_analytics.storages import Storage


class CertstreamAnalytics():
    '''
    Consume the feed of certificates from certstream, transform the data, and
    save it into various storages.
    '''

    def __init__(self, transformer=None, storage=None, analyser=None, reporter=None):
        '''
        This is the entry point of the whole module. It consumes data from
        certstream, transform it using a Transformer class, save it into
        a predefined storage (elasticsearch), and run the use-defined
        analysis.

        The transformer can be None or a subclass of CertstreamTransformer. It
        transform the raw data from certstream.

        The storage can be None or a subclass of CertstreamStorage. A sample
        kind of storage is Elasticsearch.

        The analyser can be None or a subclass of CertstreamAnalyser. It's
        entirely up to the user to decide what to do here with the transformed
        data from certstream.

        The reporter, as its name implies, collects and publishes the analyser
        result somewhere, for example, email notification. It will be a subclass
        of CertstreamReporter.
        '''
        self.transformer = transformer

        self.analyser = []
        self.reporter = []
        self.storage = []

        def _init_member(member, value, kind):
            '''
            Initialize all storages, analysers, and reporters.
            '''
            if value:
                if isinstance(value, (list, tuple)):
                    setattr(self, member, value)
                else:
                    getattr(self, member).append(value)

                for type_check in getattr(self, member):
                    if not isinstance(type_check, kind):
                        raise TypeError('Invalid {} type: {}'.format(member, type(type_check).__name__))

        _init_member('analyser', analyser, Analyser)
        _init_member('reporter', reporter, Reporter)
        _init_member('storage', storage, Storage)

        self.stopped = True
        self.thread = None

    def start(self):
        '''
        Start consuming data from certstream.
        '''
        # Run the stream in a separate thread
        self.thread = threading.Thread(target=self._consume)
        # So that it will be killed when the main thread stop
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        '''
        Stop consuming data from certstream.
        '''
        if self.stopped:
            return

        self.stopped = True
        self.thread.join()

    def _consume(self):
        '''
        Start consuming the data from certstream.
        '''
        self.stopped = False
        # pylint: disable=unnecessary-lambda
        certstream.listen_for_events(lambda m, c: self._callback(m, c),
                                     url='wss://certstream.calidog.io')

    # pylint: disable=unused-argument
    def _callback(self, message, context):
        '''
        The callback handler template itself.
        '''
        if self.stopped:
            sys.exit()

        if message['message_type'] == 'heartbeat':
            return

        if message['message_type'] == 'certificate_update':
            if self.transformer:
                # Apply the user-defined transformation. The structure of the raw
                # message is at See https://github.com/CaliDog/certstream-python/
                transformed_message = self.transformer.apply(message)
            else:
                transformed_message = message

            if self.storage and transformed_message:
                # Save the message into a more permanent storage. May be we should
                # support multiple storages in parallel here
                for storage in self.storage:
                    storage.save(transformed_message)

            if self.analyser:
                # Note that the order of analysers is extremely important cause the
                # output of an analyser will be come the input of the next analyser
                for analyser in self.analyser:
                    if not transformed_message:
                        break

                    # Run something here
                    transformed_message = analyser.run(transformed_message)

                if self.reporter and transformed_message:
                    # and report the final result
                    for reporter in self.reporter:
                        reporter.publish(transformed_message)
