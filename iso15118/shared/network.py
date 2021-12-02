import socket
import asyncio
import psutil
import logging.config
from ipaddress import IPv6Address
from random import randint
from typing import Union, Tuple

from iso15118.shared import settings
from iso15118.shared.exceptions import (NoLinkLocalAddressError,
                                        MACAddressNotFound)

logging.config.fileConfig(fname=settings.LOGGER_CONF_PATH,
                          disable_existing_loggers=False)
logger = logging.getLogger(__name__)

SDP_MULTICAST_GROUP = "FF02::1"
SDP_SERVER_PORT = 15118


def _search_link_local_addr(nic: str,
                            nic_addr_list: list) -> Union[IPv6Address, None]:
    """
    Provides the IPv6 link-local address for the network interface card
    (NIC) provided.

    Args:
        nic_addr_list   A list of tuples per network interface card (NIC),
                        each containing e.g. address family and IP address.
                        More info: https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs

    Returns:
        The first IPv6 link-local address from the given list of NIC
        addresses

    Raises:
        NoLinkLocalAddressError if no IPv6 link-local address can be found
    """
    for nic_addr in nic_addr_list:
        addr_family = nic_addr[0]
        # Remove any interface after the IP address with .split('%')[0] to
        # make sure we only get hex characters for IPv6Address(address)
        address = nic_addr[1].split('%')[0]

        if addr_family == socket.AF_INET6 and \
                IPv6Address(address).is_link_local:
            return IPv6Address(address)

    logger.debug("Could not find IPv6 link-local address for network "
                 f"interface card {nic}")
    return None


async def get_full_ipv6_address(host: str, port: int) \
        -> Tuple[str, int, int, int]:
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
    Check https://docs.python.org/3/library/asyncio-eventloop.html?highlight=getaddrinfo#asyncio.loop.getaddrinfo
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

    addr_info_list = await loop.getaddrinfo(host, port,
                                            family=socket.AF_INET6,
                                            type=socket.SOCK_STREAM)
    # We only need the socket_address here
    _, _, _, _, socket_address = addr_info_list[0]
    return socket_address


async def get_link_local_addr(port: int, evcc_settings_nic: str) \
        -> Tuple[Tuple[str, int, int, int], str]:
    """
    Provides the IPv6 link-local address for the network interface card
    (NIC) configured in the secc_settings.py file. If no NIC is configured, the
    available NICs are scanned for the first available IPv6 link-local
    address.

    psutil.net_if_addrs() returns the addresses associated to each NIC
    (network interface card) installed on the system as a dictionary whose
    keys are the NIC names and value is a list of named tuples for each
    address assigned to the NIC.
    More info: https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs

    Args:
        port:   The port used for the IPv6 link-local address
        evcc_settings_nic:    The Network Interface Card, if configured in the corresponding
                settings file (either evcc_settings.py or secc_settings.py)

    Returns:
        A tuple containing an IPv6 link-local address tuple (in the form of
        (IPv6 base address, port, flowinfo, scope_ip), where the tuple entries
        are of type Tuple[str, int, int, int]) and the network interface card

    Raises:
        NoLinkLocalAddressError if no IPv6 link-local address can be found
    """
    nics_with_addresses = psutil.net_if_addrs()

    if evcc_settings_nic:
        try:
            nic_addr_list = nics_with_addresses[evcc_settings_nic]
            ip_address = _search_link_local_addr(evcc_settings_nic,
                                                 nic_addr_list)

            if ip_address:
                nic_address = (str(ip_address) + f"%{evcc_settings_nic}")
                socket_address = await get_full_ipv6_address(
                    nic_address,
                    port)
                return socket_address, evcc_settings_nic

            raise NoLinkLocalAddressError(
                f"Network interface card (NIC) '{evcc_settings_nic}' configured in "
                "settings does not yield a local-link IPv6 address.")
        except KeyError as exc:
            raise NoLinkLocalAddressError(f"Network interface card (NIC) "
                                          f"'{evcc_settings_nic}' configured in settings but "
                                          "not found.") from exc
    else:
        # In case no NIC was provided in an EVCC or SECC settings file
        for nic in nics_with_addresses:
            ip_address = _search_link_local_addr(nic, nics_with_addresses[nic])
            # TODO: Once we move to a linux container, remove the MacOS lo0
            if ip_address and nic not in ['lo0', 'lo']:
                nic_address = str(ip_address) + f"%{nic}"
                socket_address = await get_full_ipv6_address(nic_address, port)
                return socket_address, nic

        raise NoLinkLocalAddressError("Could not find IPv6 link-local address")


def get_tcp_port() -> int:
    """
    A port number in the range of Dynamic Ports (49152-65535) as defined in
    IETF RFC 6335 are allowed for TCP.
    """
    return randint(49152, 65535)


def get_nic(settings_nic: str = None, exclude_loopback_nic: bool = False) \
        -> str:
    """
    Provides the network interface card (NIC) to use for UDP and TCP client
    and server. First, the value for settings.NETWORK_INTERFACE is
    looked up and returned, if not an empty string. If no NIC is provided
    in secc_settings.py, then the first NIC, which has an IPv6 link-local
    address, is returned.

    An example for a NIC is 'en0' or 'lo0'.
    See ifconfig on Unix-based systems and ipconfig on Windows.

    Args:
        settings_nic (str): The Network interface identifier
        exclude_loopback_nic (bool): Flag to exclude the loopback from the
                                     result
    Returns:
        A network interface card (NIC) (for example 'en0')

    Raises:
        NoLinkLocalAddressError, in the unlikely case no suitable NIC
        can be found.
    """
    if settings_nic:
        return settings_nic

    # In case no NIC was provided in an EVCC or SECC settings file
    nics_with_addresses = psutil.net_if_addrs()
    for nic in nics_with_addresses:
        ip_address = _search_link_local_addr(nic, nics_with_addresses[nic])
        if ip_address:
            if nic in ['lo0', 'lo'] and exclude_loopback_nic:
                continue
            return nic

    raise NoLinkLocalAddressError("Could not find a suitable network "
                                  "interface card with an IPv6 "
                                  "link-local address")


def get_nic_mac_address(nic_id: str = '') -> str:
    """
    This method returns the MAC Addess of a specific NIC or the first one
    associated with a IPv6 link-local address.

    psutil.net_if_addrs() returns a dict where the keys are the NIC names
    and the values are a list with the different family addresses, e.g. for en0

    {'en0': [snicaddr(family=<AddressFamily.AF_INET: 2>,
             address='192.168.21.132', netmask='255.255.255.0',
             broadcast='192.168.21.255', ptp=None),
             snicaddr(family=<AddressFamily.AF_LINK: 18>,
             address='8c:85:90:a3:96:e3',
             netmask=None, broadcast=None, ptp=None),
             snicaddr(family=<AddressFamily.AF_INET6: 30>,
             address='fe80::100d:a038:a617:6568%en0',
             netmask='ffff:ffff:ffff:ffff::',
             broadcast=None, ptp=None)
             ],
     }
    """
    nics_with_addresses = psutil.net_if_addrs()
    if not nic_id:
        try:
            nic_id = get_nic(settings_nic=nic_id, exclude_loopback_nic=True)
        except NoLinkLocalAddressError:
            raise MACAddressNotFound("Incapable of finding a suitable NIC") \
                from NoLinkLocalAddressError
    if nic_id in nics_with_addresses:
        nic = nics_with_addresses[nic_id]
        for addr in nic:
            if addr.family == psutil.AF_LINK:
                return addr.address
    raise MACAddressNotFound(f"MAC not found for NIC {nic_id}")
