import asyncio
import logging
import socket
import struct
from asyncio import DatagramTransport
from sys import platform
from typing import Optional, Tuple

from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.network import (
    SDP_MULTICAST_GROUP,
    SDP_SERVER_PORT,
    get_link_local_full_addr,
)
from iso15118.shared.notifications import (
    ReceiveTimeoutNotification,
    UDPPacketNotification,
)
from iso15118.shared.utils import wait_for_tasks

logger = logging.getLogger(__name__)


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

    def __init__(self, session_handler_queue: asyncio.Queue, iface: str):
        self.started: bool = False
        self.iface = iface
        self._session_handler_queue: asyncio.Queue = session_handler_queue
        self._rcv_queue: asyncio.Queue = asyncio.Queue()
        self._transport: Optional[DatagramTransport] = None
        self.pause_server: bool = False

    @staticmethod
    async def _create_socket(iface: str) -> socket.socket:
        """
        This method is necessary because Python does not allow
        async def __init__.
        Therefore, we need to create a separate async method to be
        our constructor.
        """
        # Initialise socket for IPv6 datagrams
        # Address family (determines network layer protocol, here IPv6)
        # Socket type (datagram, determines transport layer protocol UDP)
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

        # Block binding to this socket+interface combination from now.
        # Ref: https://www.man7.org/linux/man-pages/man7/socket.7.html
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)

        # Bind the socket to the predefined port on specified interface for receiving
        # UDP packets (SDP requests). This is done differently on Mac and Linux.
        # Reference:
        # https://djangocas.dev/blog/linux/linux-SO_BINDTODEVICE-and-mac-IP_BOUND_IF-to-bind-socket-to-a-network-interface/ # noqa
        # https://linux.die.net/man/7/socket
        # https://stackoverflow.com/questions/20616029/os-x-equivalent-of-so-bindtodevice # noqa
        if platform == "darwin":
            full_ipv6_address = await get_link_local_full_addr(SDP_SERVER_PORT, iface)
            sock.bind(full_ipv6_address)
        else:
            # Required if running on a Linux VM on Windows
            if not hasattr(socket, "SO_BINDTODEVICE"):
                socket.SO_BINDTODEVICE = 25

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                (iface + "\0").encode("ascii"),
            )
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

        interface_idx = socket.if_nametoindex(iface)
        join_multicast_group_req = multicast_group_bin + struct.pack(
            "@I", interface_idx
        )  # address + interface
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_multicast_group_req
        )

        return sock

    async def start(self, ready_event: asyncio.Event):
        """UDP server tasks to start"""
        # Get a reference to the event loop as we plan to use a low-level API
        # (see loop.create_datagram_endpoint())
        loop = asyncio.get_running_loop()
        # One protocol instance will be created to serve all client requests
        self._transport, _ = await loop.create_datagram_endpoint(
            # DatagramTransport is a subclass of BaseTransport,
            # which is not recognized by mypy
            lambda: self,
            sock=await self._create_socket(self.iface),
        )

        logger.info(
            "UDP server started at address "
            f"{SDP_MULTICAST_GROUP}%{self.iface} "
            f"and port {SDP_SERVER_PORT}"
        )
        ready_event.set()
        tasks = [self.rcv_task()]
        await wait_for_tasks(tasks)

    def connection_made(self, transport):
        """
        Callback of the lower level API, which is called when the connection to
        the socket succeeds
        """
        logger.info("UDP server socket ready")
        self.started = True

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
        if self.pause_server:
            """
            If the server is in paused state, ignore incoming datagrams.
            """
            return

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
        self.started = False

    def send(self, message: V2GTPMessage, addr: Tuple[str, int]):
        """
        This method will send the payload over the UDP socket and store the
        name of the last message sent for debugging purposes.
        """
        self._transport.sendto(message.to_bytes(), addr)

    def pause_udp_server(self):
        """
        This method will be called once a TCP connection is established with the EVCC.
        All following UDP messages will be ignored until resume_udp_server() is called
        again.
        """
        logger.info("UDP server has been paused.")
        self.pause_server = True

    def resume_udp_server(self):
        """
        Used to indicate the UDP server is ready to accept new UDP packets. Called
        once an existing TCP connection is terminated.
        """
        logger.info("UDP server has been resumed.")
        self.pause_server = False

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
