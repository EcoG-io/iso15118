import asyncio
import logging
import socket
from typing import Optional, Tuple

from iso15118.shared.network import get_link_local_full_addr, get_tcp_port
from iso15118.shared.notifications import TCPClientNotification
from iso15118.shared.security import get_ssl_context

logger = logging.getLogger(__name__)


class TCPServer(asyncio.Protocol):
    # pylint: disable=too-many-instance-attributes
    """The TCP Server handling one or more connections to EVCCs"""

    # Tuple containing the full IPV6 address as (host, port, flowinfo, scope_id)
    # For example: ('fe80::1', 64473, 0, 1)
    full_ipv6_address: Tuple[str, int, int, int]
    # The 'host' component of the full IPv6Address tuple
    # (host, port, flowinfo, scope_id)
    ipv6_address_host: str

    def __init__(self, session_handler_queue: asyncio.Queue, iface: str) -> None:
        self._session_handler_queue: asyncio.Queue = session_handler_queue
        # The dynamic TCP port number in the range of (49152-65535)
        self.port: int = get_tcp_port()
        self.iface: str = iface
        self.server: Optional[asyncio.Server] = None
        self.is_tls_enabled: bool = False

    async def start_tls(self, ready_event: asyncio.Event):
        """
        Uses the `server_factory` to start a TLS based server
        """
        await self.server_factory(ready_event, tls=True)

    async def start_no_tls(self, ready_event: asyncio.Event):
        """
        Uses the `server_factory` to start a regular TCO based server (No TLS)
        """
        await self.server_factory(ready_event, tls=False)

    async def server_factory(self, ready_event: asyncio.Event, tls: bool) -> None:
        """
        Factory method to spawn a new server.

        Configures the socket for the TCP server based on an IPv6 address,
        which is returned by the get_link_local_addr() function of the
        Network class, and binds that address to the socket.

        The TCP server is then started using the asyncio.start_server()
        function. Given the `tls` argument, an SSL context is generated and used,
        or not, to spawn the server.

        The start_serving parameter of start_server is by default set to
        True, causing the server to start accepting connections immediately.

        `asyncio.start_server` returns a Server object, more info here:
        https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server
        https://github.com/python/cpython/blob/3.9/Lib/asyncio/base_events.py#L1512
        https://github.com/python/cpython/blob/3.10/Lib/asyncio/base_events.py#L1511

        start_server is just a wrapper, for the loop.create_server, which
        takes  care of providing a factory method containing a StreamReader
        and a StreamWriter.
        Check:
        * https://github.com/python/cpython/blob/3.9/Lib/asyncio/streams.py#L58
        * https://github.com/python/cpython/blob/3.10/Lib/asyncio/streams.py#L53

        Args:
            tls (bool): flag to decide either to use tls encryption or not
        """
        ssl_context = None
        server_type = "TCP"
        self.is_tls_enabled = False
        if tls:
            ssl_context = get_ssl_context(True)
            if ssl_context is not None:
                server_type = "TLS"
                self.is_tls_enabled = True
            else:
                logger.warning(
                    "SSL context not created. Falling back to TCP connection."
                )

        MAX_RETRIES: int = 3
        BACK_OFF_SECONDS: float = 0.5
        # Note: When the socket is being created inside a container,
        # sometimes the network interface is not ready yet and the binding
        # process fails the first time.
        # Therefore, a wait-and-retry block has been added.
        for i in range(MAX_RETRIES):
            # Initialise socket for IPv6 TCP packets
            # Address family (determines network layer protocol, here IPv6)
            # Socket type (stream, determines transport layer protocol TCP)
            sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)

            # Allows address to be reused
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.full_ipv6_address = await get_link_local_full_addr(
                self.port, self.iface
            )
            self.ipv6_address_host = self.full_ipv6_address[0]

            # Bind the socket to the IP address and port for receiving
            # TCP packets
            try:
                sock.bind(self.full_ipv6_address)
                break
            except OSError as e:
                # Once the max amount of retries has been reached, reraise the exception
                if i == MAX_RETRIES - 1:
                    logger.error(f"{e} on {server_type} server.")
                    raise e
                else:
                    logger.warning(f"{e} on {server_type} server. Refreshing port...")
                    self._refresh_port()
                    logger.debug(f"Retrying on {self.port}")
                    await asyncio.sleep(BACK_OFF_SECONDS)
                    continue

        self.server = await asyncio.start_server(
            # The client_connected_cb callback, which is the __call__ method of
            # this class) is called whenever a new client connection is
            # established. It receives a StreamReader and StreamWriter pair.
            client_connected_cb=self,
            sock=sock,
            reuse_address=True,
            ssl=ssl_context,
        )

        logger.info(
            f"{server_type} server started at "
            f"address {self.ipv6_address_host}%{self.iface} and "
            f"port {self.port}"
        )

        ready_event.set()

        try:
            # Shield the task so we can handle the cancellation
            # closing the opening connections
            # Shield when cancelled, does not cancel the task within.
            # So, instead, we can control what to do with the task
            await asyncio.shield(self.server.wait_closed())
        except asyncio.CancelledError:
            logger.warning("Closing TCP server")
            self.server.close()
            await self.server.wait_closed()

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Callback for a new socket connection with the server.
        It provides a streamReader and a streamWriter
        """
        new_client = TCPClientNotification(reader, writer)

        self._session_handler_queue.put_nowait(new_client)

        # TODO check these comments below
        # The callback may be forced to be stuck here until the
        # stop event is triggered, avoiding the connection to break
        # Try this
        # await writer.wait_closed()
        # or use a asyncio.Event
        # check:
        # https://github.com/python/cpython/blob/f790bc8084d3dfd723889740f9129ac8fcb2fa02/Lib/asyncio/streams.py#L310

    def _refresh_port(self):
        random_port = get_tcp_port()
        while random_port != self.port:
            random_port = get_tcp_port()
        self.port = random_port
