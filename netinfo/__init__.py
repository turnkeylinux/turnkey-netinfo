# Copyright (c) 2010 Alon Swartz <alon@turnkeylinux.org>
#               2019-2023 TurnKey GNU/Linux <admin@turnkeylinux.org>
#
# turnkey-netinfo is open source software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.

import fcntl
import re
import socket
import struct
import subprocess
from typing import ClassVar

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
SIOCGIFBRDADDR = 0x8919

IFF_UP = 0x1  # interface is up
IFF_BROADCAST = 0x2  # vald broadcast address
IFF_DEBUG = 0x4  # internal debugging flag
IFF_LOOPBACK = 0x8  # inet is a loopback
IFF_POINTOPOINT = 0x10  # inet is ptp link
IFF_NOTRAILERS = 0x20  # avoid use of trailers
IFF_RUNNING = 0x40  # resources allocated
IFF_NOARP = 0x80  # L2 dest addr not set
IFF_PROMISC = 0x100  # promiscuous mode
IFF_ALLMULTI = 0x200  # get all multicast packets
IFF_MASTER = 0x400  # master of load balancer
IFF_SLAVE = 0x800  # slave of load balancer
IFF_MULTICAST = 0x1000  # supports multicast
IFF_PORTSEL = 0x2000  # can set media type
IFF_AUTOMEDIA = 0x4000  # auto media select active
IFF_DYNAMIC = 0x8000  # addr's lost on inet down
IFF_LOWER_UP = 0x10000  # has netif_dormant_on()
IFF_DORMANT = 0x20000  # has netif_carrier_on()


class NetInfoError(Exception):
    pass


def get_ifnames() -> list[str]:
    """returns list of interface names (up and down)"""
    ifnames = []
    with open("/proc/net/dev") as fob:
        for line in fob:
            try:
                ifname, junk = line.strip().split(":")
                ifnames.append(ifname)
            except ValueError:
                pass

    return ifnames


def get_hostname() -> str:
    return socket.gethostname()


def get_fqdn() -> str:
    return socket.getfqdn()


class InterfaceInfo:
    """enumerate network related configurations"""

    _sockfd = None

    FLAGS: ClassVar[dict[str, int]] = {}
    for attr in (
        "up",
        "broadcast",
        "debug",
        "loopback",
        "pointopoint",
        "notrailers",
        "running",
        "noarp",
        "promisc",
        "allmulti",
        "master",
        "slave",
        "multicast",
        "portsel",
        "automedia",
        "dynamic",
        "lower_up",
        "dormant",
    ):
        FLAGS[attr] = globals()["IFF_" + attr.upper()]

    def __getattr__(self, attrname: str) -> bool:
        if attrname.startswith("is_"):
            attrname = attrname[3:]

            if attrname in self.FLAGS:
                try:
                    return self._get_ioctl_flag(self.FLAGS[attrname])
                except OSError as e:
                    raise NetInfoError(
                        f"could not get {attrname} flag for {self.ifname}"
                    ) from e

        raise AttributeError(f"no such attribute: {attrname}")

    @classmethod
    def _get_sockfd(cls) -> socket.socket:
        if cls._sockfd:
            return cls._sockfd
        cls._sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return cls._sockfd

    def __init__(self, ifname: str) -> None:
        if ifname not in get_ifnames():
            raise NetInfoError(f"no such interface '{ifname}'")

        self.ifname = ifname
        self.ifreq = bytes(self.ifname + "\0" * 32, "UTF-8")[:32]

    def _get_ioctl(self, magic: int) -> bytes:
        return fcntl.ioctl(self._get_sockfd().fileno(), magic, self.ifreq)

    def _get_ioctl_addr(self, magic: int) -> str | None:
        try:
            result = self._get_ioctl(magic)
        except OSError:
            return None

        return socket.inet_ntoa(result[20:24])

    def _get_ioctl_flag(self, magic: int) -> bool:
        result = self._get_ioctl(SIOCGIFFLAGS)
        flags = struct.unpack("H", result[16:18])[0]
        return (flags & magic) != 0

    @property
    def address(self) -> str | None:
        return self._get_ioctl_addr(SIOCGIFADDR)

    addr = address

    @property
    def netmask(self) -> str | None:
        return self._get_ioctl_addr(SIOCGIFNETMASK)

    def get_gateway(self, errors: bool = False) -> str | None:
        try:
            route_n = subprocess.run(
                ["route", "-n"], capture_output=True, text=True, check=True
            ).stdout
        except subprocess.CalledProcessError as e:
            if errors:
                raise NetInfoError(e) from e
            else:
                return None

        for line in route_n.splitlines():
            regex = rf"^0.0.0.0\s+(.*?)\s+(.*)\s+{self.ifname}"
            m = re.search(regex, line, re.M)
            if m:
                return m.group(1)

        if errors:
            raise NetInfoError("No default route found!")
        else:
            return None

    @property
    def gateway(self) -> str | None:
        return self.get_gateway(errors=False)
