from asyncio.streams import StreamReader, StreamWriter
from typing import Tuple

from iso15118.shared.messages.enums import SessionStopAction


class Notification:
    """
    Base class used for notification
    """


class TCPClientNotification(Notification):
    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.transport = (reader, writer)
        self.ip_address = writer.get_extra_info("peername")


class UDPPacketNotification(Notification):
    """
    Message notification of a UDP Packet
    """

    def __init__(self, data: bytes, addr: Tuple[str, int]):
        self.data = data
        self.addr = addr

    def __len__(self):
        return len(self.data)


class ReceiveTimeoutNotification(Notification):
    """
    When the EVCC or SECC run into a timeout while waiting for the next message
    their respective communication session sends a ReceiveTimeout to the
    communication session handler.

    Args:
        message_sent:   The last message the EVCC or SECC (the entity throwing
                        the TimeoutError) sent. Only in the case of starting
                        the SECC, which is when the SECC is waiting for the
                        SupportedAppProtocol
        message_name:   The name of the last message that the EVCC or SECC sent,
                        given as an enum value of Messages
        message_timeout:    The timeout given in seconds that triggered this
                            ReceiveTimeout notification
    """


class StopNotification(Notification):
    """
    Used to indicate that the communication session shall be stopped.

    Args:
        successful: Whether the communication is stopped successfully (True) or due
                    to an error in the communication (False). The latter might cause
                    a communication session retry.
        reason: Additional information as to why the communication session is stopped.
                Helpful for further debugging.
        peer_ip_address: The IPv6 address of the peer. Relevant only for the SECC
                         to manage the various communication sessions the TCP
                         server is serving.
    """

    def __init__(
        self,
        successful: bool,
        reason: str,
        peer_ip_address: str = None,
        stop_action: SessionStopAction = SessionStopAction.TERMINATE,
    ):
        self.successful = successful
        self.reason = reason
        self.peer_ip_address = peer_ip_address
        self.stop_action = stop_action
