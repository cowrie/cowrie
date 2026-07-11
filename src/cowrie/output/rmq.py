# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.logger import Logger
from twisted.python.constants import NamedConstant, ValueConstant

import cowrie.core.output
from cowrie.core.config import CowrieConfig

_log = Logger()

try:
    import pika
    from pika.exceptions import AMQPConnectionError
except ImportError:
    _log.error("Missing dependency: pika")
    pika = None
    AMQPConnectionError = Exception


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        match o:
            case NamedConstant() | ValueConstant():
                return str(o)
            case IPv4Address() | IPv6Address():
                return o.host  # Extract the IP address as a string
            case bytes():
                return o.decode("utf-8", errors="replace")  # Convert bytes to string
            case _:
                return super().default(o)


class Output(cowrie.core.output.Output):
    """
    RabbitMQ output plugin for Cowrie using event types as routing keys,
    with reconnection logic.
    """

    _log = Logger()

    def start(self):
        """
        Initialize the RabbitMQ connection and declare the exchange.
        """
        if not pika:
            self._log.error("Pika module is not installed, RabbitMQ output disabled")
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
            self._log.info("Connected to RabbitMQ")
        except Exception as e:
            self._log.failure("Failed to connect to RabbitMQ: {error}", error=e)
            self.connection = None
            self.channel = None

    def stop(self):
        """
        Close the connection to RabbitMQ.
        """
        if self.connection:
            self.connection.close()
            self._log.info("Disconnected from RabbitMQ")

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
                    self._log.info(
                        "RabbitMQ connection is closed, attempting to reconnect"
                    )
                    self._connect()
                    if not self.connection or self.connection.is_closed:
                        self._log.error("Failed to reconnect to RabbitMQ")
                        break  # Exit loop if reconnection fails

                self.channel.basic_publish(
                    exchange=self.exchange,
                    routing_key=routing_key,
                    body=message.encode("utf-8"),
                    properties=properties,
                )
                self._log.info(
                    "Published event to RabbitMQ: {routing_key}",
                    routing_key=routing_key,
                )
                break  # Exit loop on success

            except (AMQPConnectionError, pika.exceptions.StreamLostError) as e:
                self._log.failure("AMQPConnectionError: {error}", error=e)
                self.connection = None  # Force reconnection on next attempt
                attempt += 1  # Increment attempt counter to retry
                continue  # Retry after reconnection

            except Exception as e:
                self._log.failure("Error publishing to RabbitMQ: {error}", error=e)
                break  # Exit loop on non-recoverable error
