"""
This module contains the SECC's CommunicationSessionHandler class as well as
its SECCCommunicationSession class. The former is used to initiate the SECC
and handle the SDP (SECC Discovery Protocol) exchange the EVCC, which - if
successful - will result in spawning up an SECCCommunicationSession object.
That SECCCommunicationSession object is taking care of the TCP communication
with the EVCC to properly exchange all messages in a V2G communication session.

The CommunicationSessionHandler can manage several SECCCommunicationSessions
at once, i.e. creating, storing, and deleting those sessions as needed.
"""

import asyncio
import logging
import socket
from asyncio.streams import StreamReader, StreamWriter
from typing import Dict, List, Optional, Tuple, Union

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.secc.failed_responses import (
    init_failed_responses_din_spec_70121,
    init_failed_responses_iso_v2,
    init_failed_responses_iso_v20,
)
from iso15118.secc.secc_settings import Config
from iso15118.secc.transport.tcp_server import TCPServer
from iso15118.secc.transport.udp_server import UDPServer
from iso15118.shared.comm_session import V2GCommunicationSession
from iso15118.shared.exceptions import InvalidSDPRequestError, InvalidV2GTPMessageError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.messages.enums import (
    AuthEnum,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Protocol,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    CertificateChain as CertificateChainV2,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    SAScheduleTuple,
    ServiceDetails,
    eMAID,
)
from iso15118.shared.messages.iso15118_20.common_messages import ScheduleTuple
from iso15118.shared.messages.sdp import SDPRequest, Security, create_sdp_response
from iso15118.shared.messages.timeouts import Timeouts
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.notifications import (
    StopNotification,
    TCPClientNotification,
    UDPPacketNotification,
)
from iso15118.shared.utils import cancel_task, wait_for_tasks

logger = logging.getLogger(__name__)


class SECCCommunicationSession(V2GCommunicationSession):
    """
    The communication session object for the SECC, which holds session-specific
    variables and also implements a pausing mechanism.
    """

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        session_handler_queue: asyncio.Queue,
        config: Config,
        evse_controller: EVSEControllerInterface,
    ):
        # Need to import here to avoid a circular import error
        # pylint: disable=import-outside-toplevel
        from iso15118.secc.states.sap_states import SupportedAppProtocol

        V2GCommunicationSession.__init__(
            self, transport, SupportedAppProtocol, session_handler_queue, self
        )

        self.config = config
        # The EVSE controller that implements the interface EVSEControllerInterface
        self.evse_controller = evse_controller
        # The authorization option(s) offered with ServiceDiscoveryRes in
        # ISO 15118-2 and with AuthorizationSetupRes in ISO 15118-20
        self.offered_auth_options: Optional[List[AuthEnum]] = []
        # The value-added services offered with ServiceDiscoveryRes
        self.offered_services: List[ServiceDetails] = []
        # The authorization option (called PaymentOption in ISO 15118-2) the
        # EVCC selected with the PaymentServiceSelectionReq
        self.selected_auth_option: Optional[AuthEnum] = None
        # The generated challenge sent in PaymentDetailsRes. Its copy is expected in
        # AuthorizationReq (applies to Plug & Charge identification mode only)
        self.gen_challenge: bytes = bytes(0)
        # In ISO 15118-2, the EVCCID is the MAC address, given as bytes.
        # In ISO 15118-20, the EVCCID is like a VIN number, given as str.
        self.evcc_id: Union[bytes, str, None] = None
        # The list of offered charging schedules, sent to the EVCC via the
        # ChargeParameterDiscoveryRes message (ISO 15118-2)
        self.offered_schedules: List[SAScheduleTuple] = []
        # The schedules offered with the ScheduleExchangeRes in Scheduled control mode
        # (ISO 15118-20)
        self.offered_schedules_V20: List[ScheduleTuple] = []
        # Whether or not the SECC received a PowerDeliveryReq with
        # ChargeProgress set to 'Start'
        self.charge_progress_started: bool = False
        # The contract certificate and sub-CA certificate(s) the EVCC sent
        # with the PaymentDetailsReq. Need to store in the session to verify
        # the AuthorizationReq's signature
        # TODO Add support for ISO 15118-20 CertificateChain
        self.contract_cert_chain: Optional[CertificateChainV2] = None
        # The eMAID used in plug and charge authorization.
        self.emaid: Optional[eMAID] = None
        # Initialise the failed possible responses per request message for a
        # faster lookup later when needed
        self.failed_responses_din_spec = init_failed_responses_din_spec_70121()
        self.failed_responses_isov2 = init_failed_responses_iso_v2()
        self.failed_responses_isov20 = init_failed_responses_iso_v20()
        # self.failed_responses_isov20 = init_failed_responses_iso_v20()
        # The MeterInfo value the EVCC send in the ChargingStatusRes or ,
        # CurrentDemandRes. The SECC must send a copy in the MeteringReceiptReq
        # TODO Add support for ISO 15118-20 MeterInfo
        self.sent_meter_info: Optional[MeterInfoV2] = None
        self.is_tls = self._is_tls(transport)

    def save_session_info(self):
        # TODO make sure to not delete the comm session object
        pass

    def _is_tls(self, transport: Tuple[StreamReader, StreamWriter]) -> bool:
        """
        Based on the StreamWriter, this method infers if tls is being used
        for this socket connection or not
        References:
        * https://github.com/python/cpython/blob/3.10/Lib/asyncio/streams.py#L346
        * https://github.com/python/cpython/blob/3.10/Lib/asyncio/streams.py#L236

        Args:
            transport (tuple): Tuple containing the Reader and Writer Streams

        Returns (bool): True if the connection is SSL based and False otherwise

        """
        _, writer = transport
        return True if writer.get_extra_info("sslcontext") else False


class CommunicationSessionHandler:
    """
    The CommunicationSessionHandler is the control center that manages all
    communication sessions with one or more EVs.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self, config: Config, codec: IEXICodec, evse_controller: EVSEControllerInterface
    ):

        self.list_of_tasks = []
        self.udp_server = None
        self.tcp_server = None
        self.config = config
        self.evse_controller = evse_controller

        # Set the selected EXI codec implementation
        EXI().set_exi_codec(codec)

        # Receiving queue for UDP or TCP packets and session
        # triggers (e.g. pause/terminate)
        self._rcv_queue = asyncio.Queue()

        # The comm_sessions dict keys are of type str (the IPv6 address), the
        # values are a tuple containing the SECCCommunicationSession and the
        # associated ayncio.Task object (so we can cancel the task when needed)
        self.comm_sessions: Dict[str, (SECCCommunicationSession, asyncio.Task)] = {}

    async def start_session_handler(self):
        """
        This method is necessary, because python does not allow
        async def __init__.
        Therefore, we need to create a separate async method to be our
        constructor.
        """

        self.udp_server = UDPServer(self._rcv_queue, self.config.iface)
        self.tcp_server = TCPServer(self._rcv_queue, self.config.iface)

        self.list_of_tasks = [
            self.get_from_rcv_queue(self._rcv_queue),
            self.udp_server.start(),
            self.tcp_server.start_tls(),
        ]

        if not self.config.enforce_tls:
            self.list_of_tasks.append(self.tcp_server.start_no_tls())

        logger.info("Communication session handler started")

        await wait_for_tasks(self.list_of_tasks)

    async def get_from_rcv_queue(self, queue: asyncio.Queue):
        """
        Waits for an incoming message from the transport layer
        (e.g. UDP or TCP message) or a notification from an ongoing
        communication session to pause or terminate the session.
        It will then be further processed accordingly.

        Args:
            queue:  An asyncio.Queue object, holding all the notifications the
                    SECC communication session handler needs to process
        """
        while True:
            try:
                notification = queue.get_nowait()
            except asyncio.QueueEmpty:
                notification = await queue.get()

            try:
                if isinstance(notification, UDPPacketNotification):
                    await self.process_incoming_udp_packet(notification)
                elif isinstance(notification, TCPClientNotification):
                    logger.debug(
                        "TCP client connected, client address is "
                        f"{notification.ip_address}."
                    )

                    try:
                        comm_session, task = self.comm_sessions[notification.ip_address]
                        comm_session.resume()
                    except KeyError:
                        comm_session = SECCCommunicationSession(
                            notification.transport,
                            self._rcv_queue,
                            self.config,
                            self.evse_controller,
                        )

                    task = asyncio.create_task(
                        comm_session.start(
                            Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT
                        )
                    )
                    self.comm_sessions[notification.ip_address] = (comm_session, task)
                elif isinstance(notification, StopNotification):
                    try:
                        await cancel_task(
                            self.comm_sessions[notification.peer_ip_address][1]
                        )
                        del self.comm_sessions[notification.peer_ip_address]
                    except KeyError:
                        # TODO Need to check why this KeyError happens
                        pass
                else:
                    logger.warning(
                        f"Communication session handler "
                        f"received an unknown message or "
                        f"notification: {notification}"
                    )
            # TODO: What about an except here?
            finally:
                queue.task_done()

    async def process_incoming_udp_packet(self, message: UDPPacketNotification):
        """
        We expect this to be an SDP request from the UDP client. It could be an
        SDP response with or without
        PPD (pairing and positioning device -> ACD-pantograph in ISO 15118-20)
        """
        try:
            v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, message.data)
        except InvalidV2GTPMessageError as exc:
            logger.exception(exc)
            return

        # An incoming datagram can only be an SDP request message, all
        # other messages are sent via TCP
        if v2gtp_msg.payload_type == ISOV2PayloadTypes.SDP_REQUEST:

            try:
                sdp_request = SDPRequest.from_payload(v2gtp_msg.payload)
                logger.debug(f"SDPRequest received: {sdp_request}")

                if self.config.enforce_tls or sdp_request.security == Security.TLS:
                    port = self.tcp_server.port_tls
                else:
                    port = self.tcp_server.port_no_tls

                # convert IPv6 address from presentation to numeric format
                ipv6_bytes = socket.inet_pton(
                    socket.AF_INET6, self.tcp_server.ipv6_address_host
                )

                sdp_response = create_sdp_response(
                    sdp_request, ipv6_bytes, port, self.config.enforce_tls
                )
            except InvalidSDPRequestError as exc:
                logger.exception(
                    f"{exc.__class__.__name__}, received bytes: "
                    f"{v2gtp_msg.payload.hex()}"
                )
                return
        elif v2gtp_msg.payload_type == ISOV20PayloadTypes.SDP_REQUEST_WIRELESS:
            raise NotImplementedError(
                "The incoming datagram seems to be an SECC Discovery request "
                "message for wireless communication (used for ACD-P). "
                "This feature is not yet implemented."
            )
        else:
            logger.error(
                f"Incoming datagram of {len(message.data)} "
                f"bytes is no valid SDP request message"
            )
            return

        # TODO Determine protocol version
        v2gtp_msg = V2GTPMessage(
            Protocol.ISO_15118_2,
            ISOV2PayloadTypes.SDP_RESPONSE,
            sdp_response.to_payload(),
        )
        logger.debug(f"Sending SDPResponse: {sdp_response}")

        self.udp_server.send(v2gtp_msg, message.addr)
