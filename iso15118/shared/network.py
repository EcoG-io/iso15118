import asyncio
import logging
import socket
from ipaddress import IPv6Address
from random import randint
from typing import Tuple, Union

import psutil

from iso15118.shared.exceptions import (
    InvalidInterfaceError,
    MACAddressNotFound,
    NoLinkLocalAddressError,
)

logger = logging.getLogger(__name__)

SDP_MULTICAST_GROUP = "FF02::1"
SDP_SERVER_PORT = 15118


def _get_link_local_addr(nic: str) -> Union[IPv6Address, None]:
    """
    Provides the IPv6 link-local address for the network interface card
    (NIC) address list provided.

    Args:
        nic_addr_list   A list of tuples per network interface card (NIC),
                        each containing e.g. address family and IP address.
                        More info:
                            https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs

    Returns:
        The IPv6 link-local address from the given list of NIC
        addresses, if exists

    Raises:
        NoLinkLocalAddressError if no IPv6 link-local address can be found
    """
    nics_with_addresses = psutil.net_if_addrs()
    nic_addr_list = nics_with_addresses[nic]
    for nic_addr in nic_addr_list:
        addr_family = nic_addr[0]
        # Remove any interface after the IP address with .split('%')[0] to
        # make sure we only get hex characters for IPv6Address(address)
        address = nic_addr[1].split("%")[0]

        if addr_family == socket.AF_INET6 and IPv6Address(address).is_link_local:
            return IPv6Address(address)

    raise NoLinkLocalAddressError(
        f"No link-local address was found for interface {nic}"
    )


async def _get_full_ipv6_address(host: str, port: int) -> Tuple[str, int, int, int]:
    """
    loop.getaddrinfo returns a list of tuples containing
    [(address_family, socktype, proto, canonname, socket_address)].
    As we need an IPv6 address, we can filter out all IPv4 addresses
    with getaddrinfo by specifying the family type with AF_INET6
    (instead of AF_INET). Additionally, filtering the socket type for
    TCP (by looking for socket.SOCK_STREAM) will yield just one list entry.

    In this case we will get one entry that will look like
    [ (<AddressFamily.AF_INET6: 30>, <SocketKind.SOCK_STREAM: 1>, 6, '',
    ('fe80::4fd:9dc8:b138:3bcc', 65334, 0, 5)) ]
    Check https://docs.python.org/3/library/asyncio-eventloop.html?highlight=getaddrinfo#asyncio.loop.getaddrinfo # noqa: E501
    loop.getaddrinfo is the async version of socket.getaddrinfo
    Check https://docs.python.org/3/library/socket.html#socket.getaddrinfo

    Socket_address is equal to e.g. ('fe80::4fd:9dc8:b138:3bcc', 65334, 0, 5)

    Breaking this address down, we have
    'fe80::4fd:9dc8:b138:3bcc' - IPv6 base address (host)
    65334 - the port
    0 - flowinfo
    5 - scope_id

    We need the entire socket address in order to bind it to the desired
    interface.

    For more info regarding IPv6 Addresses, check:
    https://www.notion.so/switchev/IPV6-Wiki-8c8179f74e5b4c4fb6fd6b980e58932e


    Args:
        host:   Must contain the interface associated with the ipaddress,
                e.g. 'fe80::4fd:9dc8:b138:3bcc%en0' where en0 is the
                interface
        port:   Is the port to bind the socket to

    Returns:
        A socket_address tuple (IPv6 base address, port, flowinfo, scope_ip),
        where the tuple entries are of type Tuple[str, int, int, int]
    """
    loop = asyncio.get_running_loop()

    addr_info_list = await loop.getaddrinfo(
        host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
    )
    # We only need the socket_address here
    _, _, _, _, socket_address = addr_info_list[0]
    return socket_address  # type: ignore[return-value]


def validate_nic(nic: str) -> None:
    """
    Checks if the Network Interface Card (NIC) provided exists on the system
    and contains a link-local address

    Args:
        nic (str): The network interface card identifier

    Raises:
        InterfaceNotFoundError if the specified interface could not be found
        or if no IPv6 link-local address could be found
    """
    try:
        _get_link_local_addr(nic)
    except KeyError as exc:
        raise InvalidInterfaceError(
            f"No interface {nic} with this name was found"
        ) from exc
    except NoLinkLocalAddressError as exc:
        raise InvalidInterfaceError(
            f"Interface {nic} has no link-local address " f"associated with it"
        ) from exc


async def get_link_local_full_addr(port: int, nic: str) -> Tuple[str, int, int, int]:
    """
    Provides the full IPv6 link-local address for the network interface card
    (NIC) specified. The full address contains the entire socket address, for example,

    ('fe80::4fd:9dc8:b138:3bcc', 65334, 0, 5)
    where:

    'fe80::4fd:9dc8:b138:3bcc' - is the IPv6 base address (host)
    65334 - port
    0 - flowinfo
    5 - scope_id

    Note:
        psutil.net_if_addrs() returns a dict, whose keys are the NIC names installed
        on the system and the values are a list of named tuples for each address
        assigned to the NIC.
        More info: https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs

    Args:
        port:   The port used for the IPv6 link-local address
        nic:    The Network Interface Card

    Returns:
        An IPv6 link-local address tuple (in the form of
        (IPv6 base address, port, flowinfo, scope_ip), where the tuple entries
        are of type Tuple[str, int, int, int])
    """
    ip_address = _get_link_local_addr(nic)

    nic_address = str(ip_address) + f"%{nic}"
    socket_address = await _get_full_ipv6_address(nic_address, port)
    return socket_address


def get_tcp_port() -> int:
    """
    A port number in the range of Dynamic Ports (49152-65535) as defined in
    IETF RFC 6335 are allowed for TCP.
    """
    return randint(49152, 65535)


def get_nic_mac_address(nic: str) -> str:
    """
    This method returns the MAC Addess of a specific NIC or the first one
    associated with an IPv6 link-local address.
    Args:
        nic (str): The Network Interface Card

    Returns:
        A MAC address in the format '8c:85:90:a3:96:e3' (str)

    """
    nics_with_addresses = psutil.net_if_addrs()
    nic_addr_list = nics_with_addresses[nic]
    for addr in nic_addr_list:
        if addr.family == psutil.AF_LINK:
            return addr.address
    raise MACAddressNotFound(f"MAC not found for NIC {nic}")
