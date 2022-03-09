"""
This module contains the SECC's States used to process the EVCC's incoming
V2GMessage objects of the ISO 15118-20 protocol, from SessionSetupReq to
SessionStopReq.
"""

import logging
import time
from typing import List, Union

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.states.secc_state import StateSECC
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.enums import AuthEnum, Namespace, Protocol
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationRes,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    EIMAuthSetupResParams,
    PnCAuthSetupResParams,
    ServiceDiscoveryReq,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    ResponseCode,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.iso15118_20.timeouts import Timeouts
from iso15118.shared.security import get_random_bytes, verify_signature

logger = logging.getLogger(__name__)


# ============================================================================
# |    COMMON SECC STATES (FOR ALL ENERGY TRANSFER MODES) - ISO 15118-20     |
# ============================================================================


class SessionSetup(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a SessionSetupReq from
    the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        # TODO: less the time used for waiting for and processing the
        #       SDPRequest and SupportedAppProtocolReq
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        msg = self.check_msg_v20(message, [SessionSetupReq])
        if not msg:
            return

        session_setup_req: SessionSetupReq = msg

        # Check session ID. Most likely, we need to create a new one
        session_id: str = get_random_bytes(8).hex().upper()
        if session_setup_req.header.session_id == bytes(1).hex():
            # A new charging session is established
            self.response_code = ResponseCode.OK_NEW_SESSION_ESTABLISHED
        elif session_setup_req.header.session_id == self.comm_session.session_id:
            # The EV wants to resume the previously paused charging session
            session_id = self.comm_session.session_id
            self.response_code = ResponseCode.OK_OLD_SESSION_JOINED
        else:
            # False session ID from EV, gracefully assigning new session ID
            logger.warning(
                f"EVCC's session ID {msg.header.session_id} "
                f"does not match {self.comm_session.session_id}. "
                f"New session ID {session_id} assigned"
            )
            self.response_code = ResponseCode.OK_NEW_SESSION_ESTABLISHED

        session_setup_res = SessionSetupRes(
            header=MessageHeader(session_id=session_id, timestamp=time.time()),
            response_code=self.response_code,
            evse_id=self.comm_session.evse_controller.get_evse_id(Protocol.ISO_15118_20_COMMON_MESSAGES),
        )

        self.comm_session.evcc_id = session_setup_req.evcc_id
        self.comm_session.session_id = session_id

        self.create_next_message(
            AuthorizationSetup,
            session_setup_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
        )


class AuthorizationSetup(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes an AuthorizationSetupReq
    from the EVCC.

    The EVCC may send one of the following requests in this state:
    1. an AuthorizationSetupReq
    2. an AuthorizationReq
    3. a CertificateInstallationReq
    4. a SessionStopReq

    Upon first initialisation of this state, we expect an
    AuthorizationSetupReq, but after that, the next possible request could
    be one of the others listed above. So we remain in this state until we know
    which is the following request from the EVCC and then transition to the
    appropriate state (or terminate if the incoming message doesn't fit any of
    the expected requests).

    As a result, the create_next_message() method is called with
    next_state = None.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_auth_setup_req = True

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        msg = self.check_msg_v20(
            message,
            [
                AuthorizationSetupReq,
                AuthorizationReq,
                CertificateInstallationReq,
                SessionStopReq,
            ],
            self.expecting_auth_setup_req,
        )
        if not msg:
            return

        if isinstance(msg, CertificateInstallationReq):
            CertificateInstallation(self.comm_session).process_message(message)
            return

        if isinstance(msg, AuthorizationReq):
            Authorization(self.comm_session).process_message(message)
            return

        if isinstance(msg, SessionStopReq):
            SessionStop(self.comm_session).process_message(message)
            return

        auth_options: List[AuthEnum] = []
        eim_as_res, pnc_as_res = None, None
        supported_auth_options = self.comm_session.config.supported_auth_options
        if AuthEnum.EIM in supported_auth_options:
            auth_options.append(AuthEnum.EIM)
            eim_as_res = EIMAuthSetupResParams()
        if AuthEnum.PNC in supported_auth_options:
            auth_options.append(AuthEnum.PNC)
            pnc_as_res = PnCAuthSetupResParams(
                gen_challenge=get_random_bytes(16),
                supported_providers=self.comm_session.evse_controller.get_supported_providers(),  # noqa: E501
            )
        # TODO [V2G20-2096], [V2G20-2570]

        self.comm_session.offered_auth_options = auth_options

        auth_setup_res = AuthorizationSetupRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            auth_services=auth_options,
            cert_install_service=self.comm_session.config.allow_cert_install_service,
            eim_as_res=eim_as_res,
            pnc_as_res=pnc_as_res,
        )

        self.create_next_message(
            None,
            auth_setup_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
        )

        self.expecting_auth_setup_req = False


class CertificateInstallation(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    CertificateInstallationReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("CertificateInstallation not yet implemented")


class Authorization(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes an AuthorizationReq
    from the EVCC.

    The EVCC may send one of the following requests in this state:
    1. an AuthorizationReq
    2. a CertificateInstallationReq
    3. a ServiceDiscoveryReq
    4. a SessionStopReq

    Upon first initialisation of this state, we expect an
    AuthorizationReq, but after that, the next possible request could
    be one of the others listed above. So we remain in this state until we know
    which is the following request from the EVCC and then transition to the
    appropriate state (or terminate if the incoming message doesn't fit any of
    the expected requests).

    As a result, the create_next_message() method is called with
    next_state = None.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_authorization_req = True

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        msg = self.check_msg_v20(
            message,
            [
                AuthorizationReq,
                CertificateInstallationReq,
                ServiceDiscoveryReq,
                SessionStopReq,
            ],
            self.expecting_authorization_req,
        )
        if not msg:
            return

        if isinstance(msg, CertificateInstallationReq):
            CertificateInstallation(self.comm_session).process_message(message)
            return

        if isinstance(msg, ServiceDiscoveryReq):
            ServiceDiscovery(self.comm_session).process_message(message)
            return

        if isinstance(msg, SessionStopReq):
            SessionStop(self.comm_session).process_message(message)
            return

        auth_req: AuthorizationReq = msg

        # Verify signature if EVCC sent PnC authorization data
        if auth_req.pnc_params and not verify_signature(
            auth_req.header.signature,
            [
                (
                    auth_req.pnc_params.id,
                    EXI().to_exi(auth_req.pnc_params, Namespace.ISO_V20_COMMON_MSG),
                )
            ],
            self.comm_session.contract_cert_chain.certificate,
        ):
            # TODO: There are more fine-grained WARNING response codes available
            self.stop_state_machine(
                "Unable to verify signature for AuthorizationReq",
                message,
                ResponseCode.FAILED_SIGNATURE_ERROR,
            )
            return
        else:
            if self.comm_session.evse_controller.is_authorised():
                auth_status = Processing.FINISHED
            else:
                auth_status = Processing.ONGOING
            # TODO Need to distinguish between ONGOING and WAITING_FOR_CUSTOMER

            auth_res = AuthorizationRes(
                header=MessageHeader(
                    session_id=self.comm_session.session_id, timestamp=time.time()
                ),
                response_code=ResponseCode.OK,
                evse_processing=auth_status,
            )

            self.create_next_message(
                None,
                auth_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.ISO_V20_COMMON_MSG,
            )

            if auth_status == Processing.FINISHED:
                self.expecting_authorization_req = False
            else:
                self.expecting_authorization_req = True


class ServiceDiscovery(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    ServiceDiscoveryReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("ServiceDiscovery not yet implemented")


class SessionStop(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    SessionStopReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("SessionStop not yet implemented")


# ============================================================================
# |                AC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


# ============================================================================
# |                DC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================
