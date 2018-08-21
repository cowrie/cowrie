"""
Work in progress Kafka output. Not functional yet
"""

from __future__ import absolute_import, division

import json
import logging
import random
import string

from afkak.client import KafkaClient
from afkak.partitioner import HashedPartitioner, RoundRobinPartitioner
from afkak.producer import Producer

from twisted.internet import defer, task
from twisted.python import log

import cowrie.core.output
import cowrie.python.logfile


def random_string(l, charset=string.letters.encode()):
    return b"".join(random.choice(charset) for i in range(l))


def make_messages():
    key = random_string(8)
    messages = [random_string(random.randint(20, 40))
                for i in range(random.randint(2, 25))]
    return key, messages


@defer.inlineCallbacks
def ready_client(reactor, netloc, topic):
    """
    Connect to a Kafka broker and wait for the named topic to exist.
    This assumes that ``auto.create.topics.enable`` is set in the broker
    configuration.

    :raises: `KafkaUnavailableError` if unable to connect.
    """
    client = KafkaClient(netloc, reactor=reactor)

    e = True
    while e:
        yield client.load_metadata_for_topics(topic)
        e = client.metadata_error_for_topic(topic)
        if e:
            log.info("Error getting metadata for topic %r: %s (will retry)",
                     topic, e)

    defer.returnValue(client)


@defer.inlineCallbacks
def produce(reactor, hosts='localhost:9092'):
    topic = b'example_topic'
    stop_time = reactor.seconds() + 60.0  # seconds to run
    client = yield ready_client(reactor, hosts, topic)

    producers = [
        Producer(client, RoundRobinPartitioner),
        Producer(client, HashedPartitioner),
    ]

    def cb_produce(resp):
        log.info("Produce got response: %r", resp)

    def eb_produce(f):
        log.error("Produce failed", exc_info=(f.type, f.value, f.getTracebackObject()))

    while reactor.seconds() < stop_time:
        ds = [
            # Wait at least half a second before the next send.
            task.deferLater(reactor, 0.5, lambda: None),
        ]

        # Create some number of random messages and send them to
        # the producers in parallel.
        for producer in producers:
            key, messages = make_messages()
            d = producer.send_messages(topic, key=key, msgs=messages)
            d.addCallbacks(cb_produce, eb_produce)
            ds.append(d)

        yield defer.gatherResults(ds)

    log.info("\n")
    log.info("Time is up, stopping producers...")

    for p in producers:
        p.stop()
    yield client.close()


def main():
    log.info("All Done!")


class Output(cowrie.core.output.Output):

    def __init__(self):
        cowrie.core.output.Output.__init__(self)

    def start(self):
        pass

    def stop(self):
        self.outfile.flush()

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]
            elif i == "time":
                del logentry[i]

        logging.basicConfig(
            format='%(name)s %(levelname)s %(message)s',
            level=logging.INFO,
        )
        task.react(produce, json.dumps(logentry))
