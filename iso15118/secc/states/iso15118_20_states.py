"""
This module contains the SECC's States used to process the EVCC's incoming
V2GMessage objects of the ISO 15118-20 protocol, from SessionSetupReq to
SessionStopReq.
"""
import asyncio
import logging
import time
from typing import List, Optional, Tuple, Type, Union, cast

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.states.secc_state import StateSECC
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.din_spec.datatypes import (
    ResponseCode as ResponseCodeDINSPEC,
)
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.enums import (
    AuthEnum,
    AuthorizationStatus,
    ControlMode,
    CpState,
    EVSEProcessing,
    IsolationLevel,
    ISOV20PayloadTypes,
    Namespace,
    ParameterName,
    Protocol,
    ServiceV20,
    SessionStopAction,
)
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeLoopReq,
    ACChargeLoopRes,
    ACChargeParameterDiscoveryReq,
    ACChargeParameterDiscoveryReqParams,
    ACChargeParameterDiscoveryRes,
    BPTACChargeParameterDiscoveryReqParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationRes,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    ChargeProgress,
    ChargingSession,
    EIMAuthSetupResParams,
    EVPowerProfile,
    MatchedService,
    PnCAuthSetupResParams,
    PowerDeliveryReq,
    PowerDeliveryRes,
    ScheduleExchangeReq,
    ScheduleExchangeRes,
    SelectedEnergyService,
    SelectedService,
    SelectedServiceList,
    SelectedVAS,
    ServiceDetailReq,
    ServiceDetailRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServiceIDList,
    ServiceList,
    ServiceSelectionReq,
    ServiceSelectionRes,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
    SessionStopRes,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    EVSEStatus,
    MessageHeader,
    Processing,
)
from iso15118.shared.messages.iso15118_20.common_types import ResponseCode
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryReqParams,
    DCCableCheckReq,
    DCCableCheckRes,
    DCChargeLoopReq,
    DCChargeLoopRes,
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryReqParams,
    DCChargeParameterDiscoveryRes,
    DCPreChargeReq,
    DCPreChargeRes,
    DCWeldingDetectionReq,
    DCWeldingDetectionRes,
)
from iso15118.shared.messages.iso15118_20.timeouts import Timeouts
from iso15118.shared.notifications import StopNotification
from iso15118.shared.security import get_random_bytes, verify_signature
from iso15118.shared.states import State, Terminate

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

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(message, [SessionSetupReq])
        if not msg:
            return

        session_setup_req: SessionSetupReq = cast(SessionSetupReq, msg)

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
            evse_id=await self.comm_session.evse_controller.get_evse_id(
                Protocol.ISO_15118_20_COMMON_MESSAGES
            ),
        )

        self.comm_session.evcc_id = session_setup_req.evcc_id
        self.comm_session.session_id = session_id

        self.create_next_message(
            AuthorizationSetup,
            session_setup_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
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

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
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
            await CertificateInstallation(self.comm_session).process_message(
                message, message_exi
            )
            return

        if isinstance(msg, AuthorizationReq):
            await Authorization(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        auth_options: List[AuthEnum] = []
        eim_as_res, pnc_as_res = None, None
        supported_auth_options = []
        if self.comm_session.evse_controller.is_eim_authorized():
            supported_auth_options.append(AuthEnum.EIM)
        else:
            supported_auth_options = self.comm_session.config.supported_auth_options

        if AuthEnum.PNC in supported_auth_options:
            auth_options.append(AuthEnum.PNC)
            self.comm_session.gen_challenge = get_random_bytes(16)
            pnc_as_res = PnCAuthSetupResParams(
                gen_challenge=self.comm_session.gen_challenge,
                supported_providers=await self.comm_session.evse_controller.get_supported_providers(),  # noqa: E501
            )

        if AuthEnum.EIM in supported_auth_options:
            auth_options.append(AuthEnum.EIM)
            if not pnc_as_res:
                # Only if Plug & Charge is not offered as an authorization option, then
                # we offer EIM (according to [V2G20-2567] and [V2G20-2568]). Also, the
                # XSD makes clear that either the EIM_ASResAuthorizationMode or the
                # PnC_ASResAuthorizationMode should be used, not both at the same time.
                eim_as_res = EIMAuthSetupResParams()

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
            ISOV20PayloadTypes.MAINSTREAM,
        )

        self.expecting_auth_setup_req = False


class CertificateInstallation(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    CertificateInstallationReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
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

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
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
            await CertificateInstallation(self.comm_session).process_message(
                message, message_exi
            )
            return

        if isinstance(msg, ServiceDiscoveryReq):
            await ServiceDiscovery(self.comm_session).process_message(
                message, message_exi
            )
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        auth_req: AuthorizationReq = cast(AuthorizationReq, msg)
        response_code: Optional[
            Union[ResponseCodeV2, ResponseCodeV20, ResponseCodeDINSPEC]
        ] = ResponseCode.OK
        self.comm_session.selected_auth_option = AuthEnum(
            auth_req.selected_auth_service.value
        )
        if auth_req.pnc_params:
            if not verify_signature(
                auth_req.header.signature,
                [
                    (
                        auth_req.pnc_params.id,
                        EXI().to_exi(auth_req.pnc_params, Namespace.ISO_V20_COMMON_MSG),
                    )
                ],
                auth_req.pnc_params.contract_cert_chain.certificate,
            ):
                # TODO: There are more fine-grained WARNING response codes available
                self.stop_state_machine(
                    "Unable to verify signature for AuthorizationReq",
                    message,
                    ResponseCode.FAILED_SIGNATURE_ERROR,
                )
                return

            if auth_req.pnc_params.gen_challenge != self.comm_session.gen_challenge:
                response_code = ResponseCode.WARN_CHALLENGE_INVALID

        current_authorization_status = (
            await self.comm_session.evse_controller.is_authorized()
        )
        evse_processing = Processing.ONGOING

        if resp_status := current_authorization_status.certificate_response_status:
            # Based on table 224 in ISO 15118-20 the response code should be
            # one of the following:
            # OK, OK_CERT_EXPIRES_SOON,
            # WARN_CERT_EXPIRED, WARN_CERT_NOT_YET_VALID,
            # WARN_CERT_REVOKED, WARN_CERT_VALIDATION_ERROR,
            # WARN_EMSP_UNKNOWN, WARN_GENERAL_PNC_AUTH_ERROR,
            # WARN_CHALLENGE_INVALID, WARN_AUTH_SELECTION_INVALID,
            # WARN_EIM_AUTH_FAILED, FAILED,
            # FAILED_SEQUENCE_ERROR or FAILED_UNKNOWN_SESSION

            response_code = (
                resp_status
                if resp_status
                in [
                    ResponseCode.OK,
                    ResponseCode.OK_CERT_EXPIRES_SOON,
                    ResponseCode.WARN_CERT_EXPIRED,
                    ResponseCode.WARN_CERT_NOT_YET_VALID,
                    ResponseCode.WARN_CERT_REVOKED,
                    ResponseCode.WARN_CERT_VALIDATION_ERROR,
                    ResponseCode.WARN_EMSP_UNKNOWN,
                    ResponseCode.WARN_GENERAL_PNC_AUTH_ERROR,
                    ResponseCode.WARN_CHALLENGE_INVALID,
                    ResponseCode.WARN_AUTH_SELECTION_INVALID,
                    ResponseCode.WARN_EIM_AUTH_FAILED,
                    ResponseCode.FAILED,
                    ResponseCode.FAILED_SEQUENCE_ERROR,
                    ResponseCode.FAILED_UNKNOWN_SESSION,
                ]
                else ResponseCode.FAILED
            )

        if (
            current_authorization_status.authorization_status
            == AuthorizationStatus.ACCEPTED
            and self.comm_session.evse_controller.ready_to_charge()
        ):
            evse_processing = Processing.FINISHED
        elif (
            current_authorization_status.authorization_status
            == AuthorizationStatus.ONGOING
        ):
            if self.comm_session.selected_auth_option == AuthEnum.EIM:
                evse_processing = Processing.WAITING_FOR_CUSTOMER
            else:
                evse_processing = Processing.ONGOING
        else:
            evse_processing = Processing.FINISHED

        auth_res = AuthorizationRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=response_code,
            evse_processing=evse_processing,
        )

        self.create_next_message(
            None,
            auth_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

        if evse_processing == Processing.FINISHED:
            self.expecting_authorization_req = False
        else:
            self.expecting_authorization_req = True


class ServiceDiscovery(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    ServiceDiscoveryReq from the EVCC.

    The EVCC may send one of the following requests in this state:
    1. ServiceDiscoveryReq
    2. ServiceDetailReq
    3. SessionStopReq

    Upon first initialisation of this state, we expect a ServiceDiscoveryReq
    but after that, the next possible request could be a ServiceDetailReq or a
    SessionStopReq. This means that we need to remain in this state until we receive
    the next message in the sequence.

    As a result, the create_next_message() method is called with next_state = None.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_service_discovery_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v20(
            message,
            [ServiceDiscoveryReq, ServiceDetailReq, SessionStopReq],
            self.expecting_service_discovery_req,
        )
        if not msg:
            return

        if isinstance(msg, ServiceDetailReq):
            await ServiceDetail(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        service_discovery_req: ServiceDiscoveryReq = cast(ServiceDiscoveryReq, msg)
        # TODO: Filter services based on
        #  SupportedServiceIDs field in ServiceDiscoveryReq
        offered_energy_services = (
            await self.comm_session.evse_controller.get_energy_service_list()
        )
        for energy_service in offered_energy_services.services:
            self.comm_session.matched_services_v20.append(
                MatchedService(
                    service=ServiceV20.get_by_id(energy_service.service_id),
                    is_energy_service=True,
                    is_free=energy_service.free_service,
                    # Parameter sets are available with ServiceDetailRes
                    parameter_sets=[],
                )
            )

        offered_vas = self.get_vas_list(service_discovery_req.supported_service_ids)
        if offered_vas:
            for vas in offered_vas.services:
                self.comm_session.matched_services_v20.append(
                    MatchedService(
                        service=ServiceV20.get_by_id(vas.service_id),
                        is_energy_service=False,
                        is_free=vas.free_service,
                        # Parameter sets are available with ServiceDetailRes
                        parameter_sets=[],
                    )
                )

        service_discovery_res = ServiceDiscoveryRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            service_renegotiation_supported=await self.comm_session.evse_controller.service_renegotiation_supported(),  # noqa: E501
            energy_service_list=offered_energy_services,
            vas_list=offered_vas,
        )

        self.create_next_message(
            None,
            service_discovery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

        self.expecting_service_discovery_req = False

    def get_vas_list(
        self, supported_service_ids: ServiceIDList = None
    ) -> Optional[ServiceList]:
        """
        Provides a list of value-added services (VAS) offered by the SECC. If the EVCC
        provided a SupportedServiceIDs parameter with ServiceDiscoveryReq, then the
        offered VAS list must not contain more services than the ones whose IDs are in
        this list.

        Args:
            supported_service_ids: A list that contains all ServiceIDs that the EV
                                   supports.

        Returns:
            A list of offered value-added services, or None, if none are offered.
        """
        return None


class ServiceDetail(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    ServiceDetailReq from the EVCC.

    The EVCC may send one of the following requests in this state:
    1. ServiceDetailReq
    2. ServiceSelectionReq
    3. SessionStopReq

    Upon first initialisation of this state, we expect a ServiceDetailReq
    but after that, the next possible request could be a ServiceSelectionReq or a
    SessionStopReq. This means that we need to remain in this state until we receive
    the next message in the sequence.

    As a result, the create_next_message() method is called with next_state = None.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_service_detail_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v20(
            message,
            [ServiceDetailReq, ServiceSelectionReq, SessionStopReq],
            # TODO Need to rethink this as we may also always expect a SessionStopReq,
            #      but not always a ServiceSelectionReq. The expect_first parameter
            #      doesn't work here as good as it does for ISO 15118-2
            self.expecting_service_detail_req,
        )
        if not msg:
            return

        if isinstance(msg, ServiceSelectionReq):
            await ServiceSelection(self.comm_session).process_message(
                message, message_exi
            )
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        service_detail_req: ServiceDetailReq = cast(ServiceDetailReq, msg)

        service_parameter_list = (
            await self.comm_session.evse_controller.get_service_parameter_list(
                service_detail_req.service_id
            )
        )

        is_found = False
        for offered_service in self.comm_session.matched_services_v20:
            if offered_service.service.id == service_detail_req.service_id:
                offered_service.parameter_sets = service_parameter_list.parameter_sets
                is_found = True
                break
        if is_found:
            response_code = ResponseCode.OK
        else:
            # [V2G20-464] The message "ServiceDetailRes" shall contain the
            # ResponseCode "FAILED_ServiceIDInvalid" if the ServiceID contained
            # in the ServiceDetailReq message was not part of the offered
            # EnergyTransferServiceList or VASList during ServiceDiscovery.
            response_code = ResponseCode.FAILED_SERVICE_ID_INVALID
            logger.error(f"Service Id is invalid for {message}")
        service_detail_res = ServiceDetailRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=response_code,
            service_id=service_detail_req.service_id,
            service_parameter_list=service_parameter_list,
        )

        self.create_next_message(
            None,
            service_detail_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

        self.expecting_service_detail_req = False


class ServiceSelection(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    ServiceSelectionReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v20(message, [ServiceSelectionReq, SessionStopReq], False)
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        service_selection_req: ServiceSelectionReq = cast(ServiceSelectionReq, msg)

        valid, reason, res_code = self.check_selected_services(service_selection_req)
        if not valid:
            self.stop_state_machine(reason, message, res_code)
            return

        energy_service_id = service_selection_req.selected_energy_service.service_id
        next_state: Type[State] = None
        if energy_service_id in (ServiceV20.AC.id, ServiceV20.AC_BPT.id):
            next_state = ACChargeParameterDiscovery
        elif energy_service_id in (ServiceV20.DC.id, ServiceV20.DC_BPT.id):
            next_state = DCChargeParameterDiscovery
        else:
            # TODO Implement WPT and ACDP classes to create corresponding elif-branches
            # TODO Check if the SECC offered the selected combination of service ID and
            #      parameter set ID
            self.stop_state_machine(
                f"Selected energy transfer service ID '{energy_service_id}' invalid",
                message,
                ResponseCode.FAILED_SERVICE_SELECTION_INVALID,
            )
            return

        service_selection_res = ServiceSelectionRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
        )

        self.create_next_message(
            next_state,
            service_selection_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

    def check_selected_services(
        self, service_req: ServiceSelectionReq
    ) -> Tuple[bool, str, Optional[ResponseCode]]:
        """
        Checks whether the energy transfer service and value-added services, which the
        EVCC selected, were offered by the SECC in the previous ServiceDiscoveryRes.

        Args:
            service_req: The EVCC's ServiceSelectionReq message

        Returns:
            A tuple containing the following information:
            1. True, if check passed, False otherwise
            2. If False, the reason for not passing (empty if passed)
            3. The corresponding negative response code
        """
        req_energy_service: SelectedService = service_req.selected_energy_service
        req_vas_list: SelectedServiceList = service_req.selected_vas_list

        # Create a list of tuples, with each tuple containing the service ID and the
        # associated parameter set IDs of an offered service.
        offered_id_pairs = []
        for offered_service in self.comm_session.matched_services_v20:
            offered_id_pairs.extend(offered_service.service_parameter_set_ids())

        # Let's first check if the (service ID, parameter set ID)-pair of the selected
        # energy service is valid
        if (
            req_energy_service.service_id,
            req_energy_service.parameter_set_id,
        ) not in offered_id_pairs:
            return (
                False,
                "Invalid selected pair of energy transfer service ID "
                f"'{req_energy_service.service_id}' and parameter set ID "
                f"'{req_energy_service.parameter_set_id}' (not offered by SECC)",
                ResponseCode.FAILED_NO_ENERGY_TRANSFER_SERVICE_SELECTED,
            )

        # Let's check if the (service ID, parameter set ID)-pair of all selected
        # value-added services (VAS) are valid (if the EVCC selected any VAS)
        if req_vas_list:
            for vas in req_vas_list.selected_services:
                if (vas.service_id, vas.parameter_set_id) not in offered_id_pairs:
                    return (
                        False,
                        "Invalid selected pair of value-added service ID "
                        f"'{vas.service_id}' and parameter set ID "
                        f"'{vas.parameter_set_id}' (not offered by SECC)",
                        ResponseCode.FAILED_SERVICE_SELECTION_INVALID,
                    )

        # TODO: Refactor to a separate method.
        # If all selected services are valid, let's add the information about the
        # parameter set (not just the ID) to each selected service
        for offered_service in self.comm_session.matched_services_v20:
            if req_energy_service.service_id == offered_service.service.id:
                for parameter_set in offered_service.parameter_sets:
                    if req_energy_service.parameter_set_id == parameter_set.id:
                        self.comm_session.selected_energy_service = (
                            SelectedEnergyService(
                                service=ServiceV20.get_by_id(
                                    req_energy_service.service_id
                                ),
                                is_free=offered_service.is_free,
                                parameter_set=parameter_set,
                            )
                        )

                        # Set the control mode for the comm_session object
                        for param in parameter_set.parameters:
                            if param.name == ParameterName.CONTROL_MODE:
                                self.comm_session.control_mode = ControlMode(
                                    param.int_value
                                )

                        break
                continue

            if req_vas_list:
                for vas in req_vas_list.selected_services:
                    if req_energy_service.service_id == offered_service.service.id:
                        for parameter_set in offered_service.parameter_sets:
                            if req_energy_service.parameter_set_id == parameter_set.id:
                                self.comm_session.selected_vas_list_v20.append(
                                    SelectedVAS(
                                        service=ServiceV20.get_by_id(vas.service_id),
                                        is_free=offered_service.is_free,
                                        parameter_set=parameter_set,
                                    )
                                )
                                break

        # TODO Implement [V2G20-1956] and [V2G20-1644] (ServiceRenegotiationSupported)
        # TODO Check for [V2G20-1985]

        return True, "", None


class ScheduleExchange(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    ScheduleExchangeReq from the EVCC.

    The EVCC may send one of the following requests in this state:
    1. ScheduleExchangeReq
    2. DCCableCheckReq
    3. PowerDeliveryReq
    3. SessionStopReq

    Upon first initialisation of this state, we expect a ScheduleExchangeReq
    but after that, the next possible request could be another ScheduleExchangeReq,
    a DCCableCheckReq, a PowerDeliveryReq or a SessionStopReq. This means that we need
    to remain in this state until we receive the next message in the sequence.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message,
            [ScheduleExchangeReq, DCCableCheckReq, PowerDeliveryReq, SessionStopReq],
            False,
        )
        if not msg:
            return

        if isinstance(msg, DCCableCheckReq):
            await DCCableCheck(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, PowerDeliveryReq):
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        schedule_exchange_req: ScheduleExchangeReq = cast(ScheduleExchangeReq, msg)

        scheduled_params, dynamic_params = None, None
        evse_processing = Processing.ONGOING
        if self.comm_session.control_mode == ControlMode.SCHEDULED:
            scheduled_params = (
                await self.comm_session.evse_controller.get_scheduled_se_params(
                    self.comm_session.selected_energy_service, schedule_exchange_req
                )
            )
            if scheduled_params:
                evse_processing = Processing.FINISHED
                self.comm_session.offered_schedules_V20 = (
                    scheduled_params.schedule_tuples
                )

        if self.comm_session.control_mode == ControlMode.DYNAMIC:
            dynamic_params = (
                await self.comm_session.evse_controller.get_dynamic_se_params(
                    self.comm_session.selected_energy_service, schedule_exchange_req
                )
            )
            if dynamic_params:
                evse_processing = Processing.FINISHED

        schedule_exchange_res = ScheduleExchangeRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            evse_processing=evse_processing,
            scheduled_params=scheduled_params,
            dynamic_params=dynamic_params,
        )

        # We don't know what request will come next (which state to transition to),
        # unless the schedule parameters are ready and we're in AC charging.
        # Even in DC charging the sequence is not 100% clear as the EVCC could skip
        # DCCableCheck and DCPreCharge and go straight to PowerDelivery (Pause, Standby)
        # [V2G20-2122]
        next_state = None
        if (
            evse_processing == Processing.FINISHED
            and self.comm_session.selected_energy_service.service
            in (ServiceV20.AC, ServiceV20.AC_BPT)
        ):
            next_state = PowerDelivery

        self.create_next_message(
            next_state,
            schedule_exchange_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )


class PowerDelivery(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    PowerDeliveryReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message, [PowerDeliveryReq, DCWeldingDetectionReq, SessionStopReq], False
        )
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, DCWeldingDetectionReq):
            await DCWeldingDetection(self.comm_session).process_message(
                message, message_exi
            )
            return

        power_delivery_req: PowerDeliveryReq = cast(PowerDeliveryReq, msg)

        next_state: Optional[Type[State]] = None
        header = MessageHeader(
            session_id=self.comm_session.session_id, timestamp=time.time()
        )
        response_code = ResponseCode.OK

        if power_delivery_req.ev_processing == Processing.ONGOING:
            # Initial values for next_state and response_code apply. The EVCC will send
            # another PowerDeliveryReq
            logger.debug("EV is still processing the EVPowerProfile")
        else:
            response_code = self.check_power_profile(
                power_delivery_req.ev_power_profile
            )
            if response_code in (
                ResponseCode.FAILED_EV_POWER_PROFILE_INVALID,
                ResponseCode.FAILED_EV_POWER_PROFILE_VIOLATION,
            ):
                self.stop_state_machine(
                    "EVPowerProfile invalid/violation",
                    message,
                    response_code,
                )
                return

            if (
                power_delivery_req.charge_progress == ChargeProgress.STANDBY
                and not self.comm_session.config.standby_allowed
            ):
                self.stop_state_machine(
                    "Standby not allowed",
                    message,
                    ResponseCode.WARN_STANDBY_NOT_ALLOWED,
                )
                return
            elif power_delivery_req.charge_progress == ChargeProgress.STOP:
                # According to section 8.5.6 in ISO 15118-20, the EV is out of the
                # HLC-C (High Level Controlled Charging) once
                # PowerDeliveryRes(ResponseCode=OK) is sent with a ChargeProgress=Stop
                await self.comm_session.evse_controller.set_hlc_charging(False)

                # 1st a controlled stop is performed (specially important for
                # DC charging)
                # later on we may also need here some feedback on stopping the charger
                await self.comm_session.evse_controller.stop_charger()
                # 2nd once the energy transfer is properly interrupted,
                # the contactor(s) may open

                if not await self.comm_session.evse_controller.is_contactor_opened():
                    self.stop_state_machine(
                        "Contactor didnt open",
                        message,
                        ResponseCode.FAILED_CONTACTOR_ERROR,
                    )
                    return
            else:
                # The only ChargeProgress options left are START and
                # SCHEDULE_RENEGOTIATION, although the latter is only allowed after we
                # entered the charge loop
                # TODO Check how to handle a misplaced SCHEDULE_RENEGOTIATION

                if self.comm_session.control_mode == ControlMode.SCHEDULED:
                    offered_schedules = self.comm_session.offered_schedules_V20
                    selected_schedule = (
                        power_delivery_req.ev_power_profile.scheduled_profile
                    )

                    if selected_schedule.selected_schedule_tuple_id not in [
                        schedule.schedule_tuple_id for schedule in offered_schedules
                    ]:
                        self.stop_state_machine(
                            f"Schedule with ID "
                            f"{selected_schedule.selected_schedule_tuple_id} was not "
                            f"offered",
                            message,
                            ResponseCode.FAILED_SCHEDULE_SELECTION_INVALID,
                        )
                        return

                # [V2G20-1617] The EVCC shall signal CP State B before sending the
                # first PowerDeliveryReq with ChargeProgress equals "Start" within V2G
                # communication session.
                # [V2G20 - 847] The EVCC shall signal CP State C or D no later than 250
                # ms after sending the first PowerDeliveryReq with ChargeProgress
                # equals "Start" within V2G communication session.
                if not await self.wait_for_state_c_or_d():
                    self.stop_state_machine(
                        "[V2G20-847]: State C/D not detected in PowerDelivery within"
                        " the allotted 250 ms.",
                        message,
                        ResponseCode.FAILED,
                    )
                    return

                if not await self.comm_session.evse_controller.is_contactor_closed():
                    self.stop_state_machine(
                        "Contactor didnt close",
                        message,
                        ResponseCode.FAILED_CONTACTOR_ERROR,
                    )
                    return

                # According to section 8.5.6 in ISO 15118-20, the EV enters into HLC-C
                # (High Level Controlled Charging) once
                # PowerDeliveryRes(ResponseCode=OK) is sent with a ChargeProgress=Start
                await self.comm_session.evse_controller.set_hlc_charging(True)

                if self.comm_session.selected_energy_service.service in (
                    ServiceV20.AC,
                    ServiceV20.AC_BPT,
                ):
                    next_state = ACChargeLoop
                elif self.comm_session.selected_energy_service.service in (
                    ServiceV20.DC,
                    ServiceV20.DC_BPT,
                ):
                    next_state = DCChargeLoop
                else:
                    # TODO Add support for WPT and ACDP
                    logger.error(
                        "Selected energy service not supported: "
                        f"{self.comm_session.selected_energy_service.service}"
                    )

                # TODO: Look into FAILED_PowerToleranceNotConfirmed
                #       OK_PowerToleranceConfirmed, WARNING_PowerToleranceNotConfirmed,
                #       and FAILED_PowerDeliveryNotApplied

        power_delivery_res = PowerDeliveryRes(
            header=header, response_code=response_code
        )

        self.create_next_message(
            next_state,
            power_delivery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

    async def wait_for_state_c_or_d(self) -> bool:
        # [V2G2 - 847] The EV shall signal CP State C or D no later than 250ms
        # after sending the first PowerDeliveryReq with ChargeProgress equals
        # "Start" within V2G Communication SessionPowerDeliveryReq.
        STATE_C_TIMEOUT = 0.25

        async def check_state():
            while await self.comm_session.evse_controller.get_cp_state() not in [
                CpState.C2,
                CpState.D2,
            ]:
                await asyncio.sleep(0.05)
            logger.debug(
                f"State is " f"{await self.comm_session.evse_controller.get_cp_state()}"
            )
            return True

        try:
            return await asyncio.wait_for(
                check_state(),
                timeout=STATE_C_TIMEOUT,
            )
        except asyncio.TimeoutError:
            # try one more time to get the latest state
            return await self.comm_session.evse_controller.get_cp_state() in [
                CpState.C2,
                CpState.D2,
            ]

    def check_power_profile(self, power_profile: EVPowerProfile) -> ResponseCode:
        # TODO Check the power profile for any violation
        return ResponseCode.OK


class SessionStop(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    SessionStopReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(message, [SessionStopReq], False)
        if not msg:
            return

        session_stop_req: SessionStopReq = cast(SessionStopReq, msg)

        evse_controller = self.comm_session.evse_controller
        # [V2G20-1477] : If EVSE supports ServiceRegotiation and EVCC requests
        # it in the SessionStopReq, the next state should be set to ServiceDiscoveryReq
        next_state: Type[State] = Terminate
        if (
            session_stop_req.charging_session == ChargingSession.SERVICE_RENEGOTIATION
            and await evse_controller.service_renegotiation_supported()
        ):
            next_state = ServiceDiscovery
            session_stop_state = SessionStopAction.PAUSE
        elif session_stop_req.charging_session == ChargingSession.TERMINATE:
            session_stop_state = SessionStopAction.TERMINATE
        else:
            session_stop_state = SessionStopAction.PAUSE

        termination_info = ""
        if (
            session_stop_req.ev_termination_code
            or session_stop_req.ev_termination_explanation
        ):
            termination_info = (
                f"EV termination code: '{session_stop_req.ev_termination_code}'; "
                f"EV termination explanation: '"
                f"{session_stop_req.ev_termination_explanation}'"
            )

        self.comm_session.stop_reason = StopNotification(
            True,
            f"Communication session {session_stop_state.value}d. "
            f"EV Info: {termination_info}",
            self.comm_session.writer.get_extra_info("peername"),
            session_stop_state,
        )

        session_stop_res = SessionStopRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
        )

        self.create_next_message(
            next_state,
            session_stop_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )


# ============================================================================
# |                AC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class ACChargeParameterDiscovery(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes an
    ACChargeParameterDiscoveryReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message, [ACChargeParameterDiscoveryReq, SessionStopReq], False
        )
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        ac_cpd_req: ACChargeParameterDiscoveryReq = cast(
            ACChargeParameterDiscoveryReq, msg
        )

        energy_service = self.comm_session.selected_energy_service.service
        ac_params, bpt_ac_params = None, None

        if energy_service == ServiceV20.AC and self.charge_parameter_valid(
            ac_cpd_req.ac_params
        ):
            ac_params = (
                await self.comm_session.evse_controller.get_ac_charge_params_v20(
                    ServiceV20.AC
                )
            )
        elif energy_service == ServiceV20.AC_BPT and self.charge_parameter_valid(
            ac_cpd_req.bpt_ac_params
        ):
            bpt_ac_params = (
                await self.comm_session.evse_controller.get_ac_charge_params_v20(
                    ServiceV20.AC_BPT
                )
            )
        else:
            self.stop_state_machine(
                f"Invalid charge parameter for service {energy_service}",
                message,
                ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
            )
            return

        ac_cpd_res = ACChargeParameterDiscoveryRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            ac_params=ac_params,
            bpt_ac_params=bpt_ac_params,
        )

        self.create_next_message(
            ScheduleExchange,
            ac_cpd_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_AC,
            ISOV20PayloadTypes.AC_MAINSTREAM,
        )

    def charge_parameter_valid(
        self,
        ac_charge_params: Union[
            ACChargeParameterDiscoveryReqParams, BPTACChargeParameterDiscoveryReqParams
        ],
    ) -> bool:
        # TODO Implement [V2G20-1619] (FAILED_WrongChargeParameter)
        return True


class ACChargeLoop(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes an
    ACChargeLoopReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            # TODO A MeteringConfirmationReq can come in using the multiplexed side
            #      stream. Need to figure out how to enable multiplexed communication
            message,
            [ACChargeLoopReq, PowerDeliveryReq, SessionStopReq],
            False,
        )
        if not msg:
            return

        if isinstance(msg, PowerDeliveryReq):
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        ac_charge_loop_req: ACChargeLoopReq = cast(ACChargeLoopReq, msg)

        scheduled_params, dynamic_params = None, None
        bpt_scheduled_params, bpt_dynamic_params = None, None
        selected_energy_service = self.comm_session.selected_energy_service
        control_mode = self.comm_session.control_mode

        if selected_energy_service.service == ServiceV20.AC:
            if control_mode == ControlMode.SCHEDULED:
                scheduled_params = await self.comm_session.evse_controller.get_ac_charge_loop_params_v20(  # noqa
                    ControlMode.SCHEDULED, ServiceV20.AC
                )
            elif control_mode == ControlMode.DYNAMIC:
                dynamic_params = await self.comm_session.evse_controller.get_ac_charge_loop_params_v20(  # noqa
                    ControlMode.DYNAMIC, ServiceV20.AC
                )  # noqa
        elif selected_energy_service.service == ServiceV20.AC_BPT:
            if control_mode == ControlMode.SCHEDULED:
                bpt_scheduled_params = await self.comm_session.evse_controller.get_ac_charge_loop_params_v20(  # noqa
                    ControlMode.SCHEDULED, ServiceV20.AC_BPT
                )  # noqa
            else:
                bpt_dynamic_params = await self.comm_session.evse_controller.get_ac_charge_loop_params_v20(  # noqa
                    ControlMode.DYNAMIC, ServiceV20.AC_BPT
                )  # noqa

                # For now we just do this for the Dynamic Mode
                ev_bpt_charge_parameters = ac_charge_loop_req.bpt_dynamic_params.dict()
                # extract only the power limits and convert them to decimal
                # representation
                ev_power_limits = {}
                for k, v in ev_bpt_charge_parameters.items():
                    if type(v) is dict:
                        ev_power_limits.update({k: v["value"] * 10 ** v["exponent"]})
                # update the dict with the decimal values
                ev_bpt_charge_parameters.update(ev_power_limits)
                # update the ev_data_context
                self.comm_session.evse_controller.ev_data_context.update(
                    ev_bpt_charge_parameters
                )
                await self.comm_session.evse_controller.send_charging_power_limits(
                    self.comm_session.protocol,
                    control_mode,
                    selected_energy_service.service,
                )
        else:
            logger.error(
                f"Energy service {selected_energy_service.service} not yet supported"
            )
            return

        meter_info = None
        if ac_charge_loop_req.meter_info_requested:
            meter_info = await self.comm_session.evse_controller.get_meter_info_v20()

        evse_status: Optional[
            EVSEStatus
        ] = await self.comm_session.evse_controller.get_evse_status()

        ac_charge_loop_res = ACChargeLoopRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            ),
            evse_status=evse_status,
            # TODO Check for other failed or warning response codes
            response_code=ResponseCode.OK,
            scheduled_params=scheduled_params,
            dynamic_params=dynamic_params,
            bpt_scheduled_params=bpt_scheduled_params,
            bpt_dynamic_params=bpt_dynamic_params,
            meter_info=meter_info,
        )

        self.create_next_message(
            None,
            ac_charge_loop_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_AC,
            ISOV20PayloadTypes.AC_MAINSTREAM,
        )

    def check_power_profile(self) -> ResponseCode:
        # TODO Check the power profile for any violation
        return ResponseCode.OK


# ============================================================================
# |                DC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class DCChargeParameterDiscovery(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    DCChargeParameterDiscoveryReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message, [DCChargeParameterDiscoveryReq, SessionStopReq], False
        )
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        dc_cpd_req: DCChargeParameterDiscoveryReq = cast(
            DCChargeParameterDiscoveryReq, msg
        )

        energy_service = self.comm_session.selected_energy_service.service
        dc_params, bpt_dc_params = None, None

        if energy_service == ServiceV20.DC and self.charge_parameter_valid(
            dc_cpd_req.dc_params
        ):
            dc_params = (
                await self.comm_session.evse_controller.get_dc_charge_params_v20(
                    ServiceV20.DC
                )
            )
        elif energy_service == ServiceV20.DC_BPT and self.charge_parameter_valid(
            dc_cpd_req.bpt_dc_params
        ):
            bpt_dc_params = (
                await self.comm_session.evse_controller.get_dc_charge_params_v20(
                    ServiceV20.DC_BPT
                )
            )
        else:
            self.stop_state_machine(
                f"Invalid charge parameter for service {energy_service}",
                message,
                ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
            )
            return

        dc_cpd_res = DCChargeParameterDiscoveryRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            dc_params=dc_params,
            bpt_dc_params=bpt_dc_params,
        )

        self.create_next_message(
            ScheduleExchange,
            dc_cpd_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        )

    def charge_parameter_valid(
        self,
        dc_charge_params: Union[
            DCChargeParameterDiscoveryReqParams, BPTDCChargeParameterDiscoveryReqParams
        ],
    ) -> bool:
        # TODO Implement [V2G20-2272] (FAILED_WrongChargeParameter)
        return True


class DCCableCheck(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    DCCableCheckReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.cable_check_req_was_received = False

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message, [DCCableCheckReq, SessionStopReq], False
        )
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        if not self.cable_check_req_was_received:
            # First DCCableCheckReq received. Start cable check.
            await self.comm_session.evse_controller.start_cable_check()

            # Requirement in 6.4.3.106 of the IEC 61851-23
            # Any relays in the DC output circuit of the DC station shall
            # be closed during the insulation test
            if not await self.comm_session.evse_controller.is_contactor_closed():
                self.stop_state_machine(
                    "Contactor didnt close for Cable Check",
                    message,
                    ResponseCode.FAILED,
                )
                return

            self.cable_check_req_was_received = True

        next_state = None
        processing = EVSEProcessing.ONGOING
        isolation_level = (
            await self.comm_session.evse_controller.get_cable_check_status()
        )

        if isolation_level in [IsolationLevel.VALID, IsolationLevel.WARNING]:
            if isolation_level == IsolationLevel.WARNING:
                logger.warning(
                    "Isolation resistance measured by EVSE is in Warning range"
                )
            next_state = DCPreCharge
            processing = EVSEProcessing.FINISHED
        elif isolation_level in [IsolationLevel.INVALID, IsolationLevel.FAULT]:
            self.stop_state_machine(
                f"Isolation Failure: {isolation_level}",
                message,
                ResponseCode.FAILED,
            )
            return

        dc_cable_check_res = DCCableCheckRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            evse_processing=processing,
        )

        self.create_next_message(
            next_state,
            dc_cable_check_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        )


class DCPreCharge(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    DCPreChargeReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_precharge_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message,
            [DCPreChargeReq, PowerDeliveryReq],
            self.expecting_precharge_req,
        )
        if not msg:
            return

        if isinstance(msg, PowerDeliveryReq):
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

        precharge_req: DCPreChargeReq = cast(DCPreChargeReq, msg)
        self.expecting_precharge_req = False

        next_state: Type[StateSECC] = None
        if precharge_req.ev_processing == Processing.FINISHED:
            next_state = PowerDelivery
        else:
            await self.comm_session.evse_controller.set_precharge(
                precharge_req.ev_target_voltage, precharge_req.ev_present_voltage
            )

        dc_precharge_res = DCPreChargeRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            evse_present_voltage=await self.comm_session.evse_controller.get_evse_present_voltage(  # noqa
                Protocol.ISO_15118_20_DC
            ),
        )
        self.create_next_message(
            next_state,
            dc_precharge_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        )


class DCChargeLoop(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    DCChargeLoopReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_charge_loop_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message, [DCChargeLoopReq, PowerDeliveryReq], self.expecting_charge_loop_req
        )
        if not msg:
            return

        if isinstance(msg, PowerDeliveryReq):
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

        self.expecting_charge_loop_req = False

        dc_charge_loop_res = await self.build_dc_charge_loop_res()
        self.create_next_message(
            None,
            dc_charge_loop_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        )

    async def build_dc_charge_loop_res(self) -> DCChargeLoopRes:
        scheduled_params, dynamic_params = None, None
        bpt_scheduled_params, bpt_dynamic_params = None, None
        selected_energy_service = self.comm_session.selected_energy_service
        control_mode = self.comm_session.control_mode
        response_code = ResponseCode.OK
        if selected_energy_service.service == ServiceV20.DC:
            if control_mode == ControlMode.SCHEDULED:
                scheduled_params = await self.comm_session.evse_controller.get_dc_charge_loop_params_v20(  # noqa
                    ControlMode.SCHEDULED, ServiceV20.DC
                )
            elif control_mode == ControlMode.DYNAMIC:
                dynamic_params = await self.comm_session.evse_controller.get_dc_charge_loop_params_v20(  # noqa
                    ControlMode.DYNAMIC, ServiceV20.DC
                )
        elif selected_energy_service.service == ServiceV20.DC_BPT:
            if control_mode == ControlMode.SCHEDULED:
                bpt_scheduled_params = await self.comm_session.evse_controller.get_dc_charge_loop_params_v20(  # noqa
                    ControlMode.SCHEDULED, ServiceV20.DC_BPT
                )
            else:
                bpt_dynamic_params = await self.comm_session.evse_controller.get_dc_charge_loop_params_v20(  # noqa
                    ControlMode.DYNAMIC, ServiceV20.DC_BPT
                )
        else:
            logger.error(
                f"Energy service {selected_energy_service.service} not yet supported"
            )
            response_code = ResponseCode.FAILED_SERVICE_SELECTION_INVALID

        evse_status: Optional[
            EVSEStatus
        ] = await self.comm_session.evse_controller.get_evse_status()

        dc_charge_loop_res = DCChargeLoopRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            evse_status=evse_status,
            response_code=response_code,
            evse_present_current=await self.comm_session.evse_controller.get_evse_present_current(  # noqa
                Protocol.ISO_15118_20_DC
            ),  # noqa
            evse_present_voltage=await self.comm_session.evse_controller.get_evse_present_voltage(  # noqa
                Protocol.ISO_15118_20_DC
            ),  # noqa
            evse_power_limit_achieved=await self.comm_session.evse_controller.is_evse_power_limit_achieved(),  # noqa
            evse_current_limit_achieved=await self.comm_session.evse_controller.is_evse_current_limit_achieved(),  # noqa
            evse_voltage_limit_achieved=await self.comm_session.evse_controller.is_evse_voltage_limit_achieved(),  # noqa
            scheduled_dc_charge_loop_res=scheduled_params,
            dynamic_dc_charge_loop_res=dynamic_params,
            bpt_scheduled_dc_charge_loop_res=bpt_scheduled_params,
            bpt_dynamic_dc_charge_loop_res=bpt_dynamic_params,
        )
        return dc_charge_loop_res


class DCWeldingDetection(StateSECC):
    """
    The ISO 15118-20 state in which the SECC processes a
    DCWeldingDetectionReq from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)
        self.expecting_welding_detection_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg: V2GMessageV20 = self.check_msg_v20(
            message,
            [DCWeldingDetectionReq, SessionStopReq],
            self.expecting_welding_detection_req,
        )
        if not msg:
            return

        if isinstance(msg, SessionStopReq):
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        self.expecting_welding_detection_req = False
        welding_detection_res = DCWeldingDetectionRes(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            ),
            response_code=ResponseCode.OK,
            evse_present_voltage=await self.comm_session.evse_controller.get_evse_present_voltage(  # noqa
                Protocol.ISO_15118_20_DC
            ),  # noqa
        )

        self.create_next_message(
            None,
            welding_detection_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        )
