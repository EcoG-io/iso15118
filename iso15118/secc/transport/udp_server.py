import asyncio
import logging.config
import socket
import struct
from asyncio import DatagramTransport
from typing import Tuple

from iso15118.secc import secc_settings
from iso15118.shared import settings
from iso15118.shared.exceptions import NoLinkLocalAddressError
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.network import SDP_MULTICAST_GROUP, SDP_SERVER_PORT, get_nic
from iso15118.shared.notifications import (
    ReceiveTimeoutNotification,
    UDPPacketNotification,
)
from iso15118.shared.utils import wait_till_finished

logging.config.fileConfig(
    fname=settings.LOGGER_CONF_PATH, disable_existing_loggers=False
)
logger = logging.getLogger(__name__)

# TODO should be coming from SLAC
IFACE = "en0"


class UDPServer(asyncio.DatagramProtocol):
    """
    The UDPServer makes use of asyncio and its concepts of 'transports' and
    'protocols'. A transport is an abstraction for a socket
    (how bytes are transmitted), while the protocol determines which bytes to
    transmit (and to some extent when).

    There is always a 1:1 relationship between transport and protocol objects:
    the protocol calls transport methods to send data, while the transport
    calls protocol methods to pass it data that has been received.

    asyncio implements transports for TCP, UDP, SSL, and subprocess pipes.
    We use asyncio.DatagramTransport for UDP.
    For more information check:
    https://docs.python.org/3/library/asyncio-protocol.html
    """

    _transport: DatagramTransport
    _last_message_sent: V2GTPMessage

    def __init__(self, session_handler_queue: asyncio.Queue):
        self._closed = False
        self._session_handler_queue: asyncio.Queue = session_handler_queue
        self._rcv_queue: asyncio.Queue = asyncio.Queue()

    @staticmethod
    async def create(session_handler_queue: asyncio.Queue) -> "UDPServer":
        """
        This method is necessary because Python does not allow
        async def __init__.
        Therefore, we need to create a separate async method to be
        our constructor.
        """
        # Get a reference to the event loop as we plan to use a low-level API
        # (see loop.create_datagram_endpoint())
        loop = asyncio.get_running_loop()

        self = UDPServer(session_handler_queue)

        # Initialise socket for IPv6 datagrams
        # Address family (determines network layer protocol, here IPv6)
        # Socket type (datagram, determines transport layer protocol UDP)
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

        # Allows address to be reused
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the predefined port for receiving
        # UDP packets (SDP requests)
        sock.bind(("", SDP_SERVER_PORT))

        # After the regular socket is created and bound to a port, it can be
        # added to the multicast group by using setsockopt() to set the
        # IPV6_JOIN_GROUP option. The option value is the 16-byte packed
        # representation of the multicast group address followed by the network
        # interface on which the server should listen for the traffic.
        # Therefore, we use socket.inet_pton() to convert an IP address from
        # its family-specific string format to a packed, binary format.
        # struct is a way to encode C structures as byte strings
        # pton stands for "Presentation TO Numeric"
        # aton stands for "Ascii TO Numeric"
        multicast_group_bin = socket.inet_pton(socket.AF_INET6, SDP_MULTICAST_GROUP)

        nic: str = ""

        try:
            nic = get_nic(secc_settings.NETWORK_INTERFACE)
        except NoLinkLocalAddressError as exc:
            logger.exception(
                "Could not assign an interface for the UDP "
                "server, unable to find network interface card. "
                f"{exc}"
            )

        interface_idx = socket.if_nametoindex(nic)
        join_multicast_group_req = (
            multicast_group_bin
            + struct.pack("@I", interface_idx)  # address + interface
        )
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_multicast_group_req
        )

        # One protocol instance will be created to serve all client requests
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            sock=sock,
            reuse_address=True,
        )

        self._transport = transport

        logger.debug(
            "UDP server started at address "
            f"{SDP_MULTICAST_GROUP}%{nic} "
            f"and port {SDP_SERVER_PORT}"
        )

        return self

    # def connection_made(self, transport):
    #     """
    #     Callback of the lower level API when the connection to
    #     the socket succeeded
    #     """
    #     logger.debug("UDP server socket ready")
    #     self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """
        Callback from asyncio.DatagramProtocol (which receives all packets)
        when a UDP client sent data.
        That data is put into a receiving queue that feeds into the
        communication session handler queue after.

        Args:
            data: A bytes object containing the incoming data
            addr: The address of the peer sending the data; the exact format
            depends on the transport.
        """
        logger.debug(f"Message received from {addr}: {data.hex()}")
        try:
            udp_packet = UDPPacketNotification(bytearray(data), addr)
            self._rcv_queue.put_nowait((udp_packet, addr))
        except asyncio.QueueFull:
            logger.error(f"Dropped packet size {len(data)} from {addr}")

    def error_received(self, exc):
        """
        Callback from asyncio.DatagramProtocol when a previous send or
        receive operation raises an OSError

        Args:
            exc: The OSError instance
        """
        logger.exception(f"Server received an error: {exc}")

    def connection_lost(self, exc):
        """
        Callback from asyncio.DatagramProtocol when a connection is lost

        Args:
            exc: Either an exception object or None. The latter means a regular
            EOF is received, or the connection was aborted or closed by this
            side of the connection.
        """
        reason = f". Reason: {exc}" if exc else ""
        logger.exception(f"UDP server closed. {reason}")
        self._closed = True

    async def start(self):
        """UDP server tasks to start"""
        tasks = [self.rcv_task()]
        await wait_till_finished(tasks)

    def send(self, message: V2GTPMessage, addr: Tuple[str, int]):
        """
        This method will send the payload over the UDP socket and store the
        name of the last message sent for debugging purposes.
        """
        self._transport.sendto(message.to_bytes(), addr)
        self._last_message_sent = message

    async def rcv_task(self, timeout: int = None):
        """
        This receive task is waiting for a specified time for an answer to the
        last message sent via UDP. Once a message is received, it is relayed to
        communication session handler queue.

        If no answer arrives on time in the rcv queue, an exception is thrown
        and a ReceiveTimeoutNotification is sent to the communication session
        layer.
        """
        while True:
            try:
                udp_packet, _ = await asyncio.wait_for(
                    self._rcv_queue.get(), timeout=timeout
                )
                self._session_handler_queue.put_nowait(udp_packet)
            except asyncio.TimeoutError:
                timeout_notification = ReceiveTimeoutNotification()
                self._session_handler_queue.put_nowait(timeout_notification)
