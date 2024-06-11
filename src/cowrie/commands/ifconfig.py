# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from random import randint, randrange

from cowrie.shell.command import HoneyPotCommand

HWaddr = f"{randint(0, 255):02x}:{randint(0, 255):02x}:{randint(0, 255):02x}:{randint(0, 255):02x}:{randint(0, 255):02x}:{randint(0, 255):02x}"

inet6 = f"fe{randint(0, 255):02x}::{randrange(111, 888):02x}:{randint(0, 255):02x}ff:fe{randint(0, 255):02x}:{randint(0, 255):02x}01/64"

commands = {}


class Command_ifconfig(HoneyPotCommand):
    @staticmethod
    def generate_packets() -> int:
        return randrange(222222, 555555)

    @staticmethod
    def convert_bytes_to_mx(bytes_eth0: int) -> str:
        mb = float(bytes_eth0) / 1000 / 1000
        return f"{mb:.1f}"

    def calculate_rx(self) -> tuple[int, str]:
        rx_bytes = randrange(111111111, 555555555)
        return rx_bytes, self.convert_bytes_to_mx(rx_bytes)

    def calculate_tx(self) -> tuple[int, str]:
        rx_bytes = randrange(11111111, 55555555)
        return rx_bytes, self.convert_bytes_to_mx(rx_bytes)

    def calculate_lo(self) -> tuple[int, str]:
        lo_bytes = randrange(11111111, 55555555)
        return lo_bytes, self.convert_bytes_to_mx(lo_bytes)

    def call(self) -> None:
        rx_bytes_eth0, rx_mb_eth0 = self.calculate_rx()
        tx_bytes_eth0, tx_mb_eth0 = self.calculate_tx()
        lo_bytes, lo_mb = self.calculate_lo()
        rx_packets = self.generate_packets()
        tx_packets = self.generate_packets()
        result = """eth0      Link encap:Ethernet  HWaddr {}
          inet addr:{}  Bcast:{}.255  Mask:255.255.255.0
          inet6 addr: {} Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:{} errors:0 dropped:0 overruns:0 frame:0
          TX packets:{} errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:{} ({} MB)  TX bytes:{} ({} MB)


lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:110 errors:0 dropped:0 overruns:0 frame:0
          TX packets:110 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:{} ({} MB)  TX bytes:{} ({} MB)""".format(
            HWaddr,
            self.protocol.kippoIP,
            self.protocol.kippoIP.rsplit(".", 1)[0],
            inet6,
            rx_packets,
            tx_packets,
            rx_bytes_eth0,
            rx_mb_eth0,
            tx_bytes_eth0,
            tx_mb_eth0,
            lo_bytes,
            lo_mb,
            lo_bytes,
            lo_mb,
        )
        self.write(f"{result}\n")


commands["/sbin/ifconfig"] = Command_ifconfig
commands["ifconfig"] = Command_ifconfig
