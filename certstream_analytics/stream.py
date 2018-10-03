'''
All hail [certstream](https://github.com/CaliDog/certstream-python)!!

This module consumes the feed of certificates from certstream and does
the heavy lifting.
'''
import sys
import threading
import certstream


class CertstreamAnalytics():
    '''
    Consume the feed of certificates from certstream, transform the data, and
    save it into various storages.
    '''

    def __init__(self, transformer=None, storage=None, analyser=None):
        '''
        This is the entry point of the whole module. It consumes data from
        certstream, transform it using a Transformer class, save it into
        a predefined storage (elasticsearch), and run the use-defined
        analysis.

        The transformer can be None or a subclass of CertstreamTransformer.

        The storage can be None or a subclass of CertstreamStorage.

        The analyser can be None or a subclass of CertstreamAnalyser.
        '''
        self.transformer = transformer
        self.storage = storage
        self.analyser = analyser

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
        # pylint: disable=unnecessary-lambda
        callback = lambda message, context: self._callback(message, context)

        self.stopped = False
        # The road goes ever on and on
        certstream.listen_for_events(callback, url='wss://certstream.calidog.io')

    # pylint: disable=unused-argument
    def _callback(self, message, context):
        '''
        The callback handler template itself.
        '''
        if self.stopped:
            sys.exit()

        if message['message_type'] == "heartbeat":
            return

        if message['message_type'] == "certificate_update":
            if self.transformer:
                # Apply the user-defined transformation. The structure of the raw
                # message is at See https://github.com/CaliDog/certstream-python/
                transformed_message = self.transformer.apply(message)
            else:
                transformed_message = message

            if self.storage and transformed_message:
                # Save the message into a more permanent storage. May be we should
                # support multiple storages here
                self.storage.save(transformed_message)

            if self.analyser and transformed_message:
                # Run something here, will you
                self.analyser.run(transformed_message)
