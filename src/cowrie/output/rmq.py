from __future__ import annotations

import json

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.python import log
from twisted.python.constants import NamedConstant, ValueConstant

import cowrie.core.output
from cowrie.core.config import CowrieConfig

try:
    import pika
    from pika.exceptions import AMQPConnectionError
except ImportError:
    log.err("Missing dependency: pika")
    pika = None


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (NamedConstant, ValueConstant)):
            return str(obj)
        elif isinstance(obj, (IPv4Address, IPv6Address)):
            return obj.host  # Extract the IP address as a string
        elif isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")  # Convert bytes to string
        else:
            return super().default(obj)


class Output(cowrie.core.output.Output):
    """
    RabbitMQ output plugin for Cowrie using event types as routing keys,
    with reconnection logic.
    """

    def start(self):
        """
        Initialize the RabbitMQ connection and declare the exchange.
        """
        if not pika:
            log.err("Pika module is not installed, RabbitMQ output disabled")
            return

        self.host = CowrieConfig.get("output_rmq", "host", fallback="localhost")
        self.port = CowrieConfig.getint("output_rmq", "port", fallback=5672)
        self.username = CowrieConfig.get("output_rmq", "username", fallback="guest")
        self.password = CowrieConfig.get("output_rmq", "password", fallback="guest")
        self.vhost = CowrieConfig.get("output_rmq", "vhost", fallback="/")
        self.exchange = CowrieConfig.get("output_rmq", "exchange", fallback="cowrie")
        self.exchange_type = CowrieConfig.get(
            "output_rmq", "exchange_type", fallback="topic"
        )

        self._connect()

    def _connect(self):
        """
        Establish a connection to RabbitMQ and declare the exchange.
        """
        credentials = pika.PlainCredentials(self.username, self.password)
        parameters = pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            virtual_host=self.vhost,
            credentials=credentials,
            heartbeat=600,  # Adjust the heartbeat interval as needed
        )

        try:
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            self.channel.exchange_declare(
                exchange=self.exchange,
                exchange_type=self.exchange_type,
                durable=True,
            )
            log.msg("Connected to RabbitMQ")
        except Exception as e:
            log.err(f"Failed to connect to RabbitMQ: {e}")
            self.connection = None
            self.channel = None

    def stop(self):
        """
        Close the connection to RabbitMQ.
        """
        if self.connection:
            self.connection.close()
            log.msg("Disconnected from RabbitMQ")

    def write(self, event):
        """
        Publish an event to the RabbitMQ exchange using event type as routing key,
        with reconnection logic.
        """
        if not pika:
            return  # Pika not available, cannot proceed

        # Ensure the message is serializable
        message = json.dumps(event, cls=CustomJSONEncoder)
        properties = pika.BasicProperties(content_type="application/json")
        routing_key = event.get("eventid", "cowrie.unknown")

        # Attempt to publish the message, with reconnection logic
        attempt = 0
        while attempt < 2:  # Try at most twice
            try:
                if not self.connection or self.connection.is_closed:
                    log.msg("RabbitMQ connection is closed, attempting to reconnect")
                    self._connect()
                    if not self.connection or self.connection.is_closed:
                        log.err("Failed to reconnect to RabbitMQ")
                        break  # Exit loop if reconnection fails

                self.channel.basic_publish(
                    exchange=self.exchange,
                    routing_key=routing_key,
                    body=message.encode("utf-8"),
                    properties=properties,
                )
                log.msg(f"Published event to RabbitMQ: {routing_key}")
                break  # Exit loop on success

            except (AMQPConnectionError, pika.exceptions.StreamLostError) as e:
                log.err(f"AMQPConnectionError: {e}")
                self.connection = None  # Force reconnection on next attempt
                attempt += 1  # Increment attempt counter to retry
                continue  # Retry after reconnection

            except Exception as e:
                log.err(f"Error publishing to RabbitMQ: {e}")
                break  # Exit loop on non-recoverable error
