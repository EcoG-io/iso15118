"""
This module contains the SECC's States used to process the EVCC's incoming
V2GMessage objects of the DIN SPEC 70121 protocol, from SessionSetupReq to
SessionStopReq.
"""

import logging
import time
from typing import List, Union

from iso15118.shared.states import Terminate

from iso15118.shared.notifications import StopNotification

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.states.secc_state import StateSECC
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.enums import AuthEnum, Namespace, Protocol, EVSEProcessing
from iso15118.shared.messages.din_spec.body import (
    SessionSetupReq,
    SessionSetupRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServicePaymentSelectionReq,
    ServicePaymentSelectionRes,
    ContractAuthenticationReq,
    ContractAuthenticationRes,
    SessionStopReq,
    SessionStopRes,
    ChargeParameterDiscoveryRes,
    ChargeParameterDiscoveryReq,
    CableCheckReq,
    CableCheckRes,
    PreChargeReq,
    PreChargeRes,
    PowerDeliveryRes,
    PowerDeliveryReq,
    CurrentDemandRes,
    CurrentDemandReq,
    WeldingDetectionReq,
    WeldingDetectionRes,
)
from iso15118.shared.messages.iso15118_2.body import (
    ResponseCode,
)
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.din_spec.timeouts import Timeouts
from iso15118.shared.security import get_random_bytes
from iso15118.shared.messages.din_spec.datatypes import (
    ServiceCategory,
    ServiceDetails,
    ChargeService,
    AuthOptionList,
    ServiceID,
    SAScheduleList,
)

logger = logging.getLogger(__name__)


# ============================================================================
# |            SECC STATES - DIN SPEC 70121                                  |
# ============================================================================


class SessionSetup(StateSECC):
    """
    The DIN SPEC state in which the SECC processes a SessionSetupReq
    message from the EVCC.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATIONSETUP_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [SessionSetupReq])
        if not msg:
            return

        session_setup_req: SessionSetupReq = msg.body.session_setup_req

        # Check session ID. Most likely, we need to create a new one
        session_id: str = get_random_bytes(8).hex().upper()
        if msg.header.session_id == bytes(1).hex():
            # A new charging session is established
            self.response_code = ResponseCode.OK_NEW_SESSION_ESTABLISHED
        elif msg.header.session_id == self.comm_session.session_id:
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
            response_code=self.response_code,
            evse_id=self.comm_session.evse_controller.get_evse_id(
                Protocol.DIN_SPEC_70121
            ),
            datetime_now=time.time(),
        )

        self.comm_session.evcc_id = session_setup_req.evcc_id
        self.comm_session.session_id = session_id

        self.create_next_message(
            ServiceDiscovery,
            session_setup_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class ServiceDiscovery(StateSECC):
    """
    The DIN SPEC state in which the SECC processes a ServiceDiscoveryReq
    message from the EVCC.

    By sending the ServiceDiscoveryReq message, the EVCC triggers the SECC
    to send information about all services offered by the SECC.
    Furthermore, the EVCC can limit for particular services by using the
    service scope and service type elements.
    However, in DIN SPEC, ServiceCategory, if used, must be set to "EVCharging"
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [ServiceDiscoveryReq])
        if not msg:
            return

        service_discovery_req: ServiceDiscoveryReq = msg.body.service_discovery_req
        service_discovery_res = self.get_services(
            service_discovery_req.service_category
        )

        self.create_next_message(
            ServiceAndPaymentSelection,
            service_discovery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )

    def get_services(self, category_filter: ServiceCategory) -> ServiceDiscoveryRes:
        """
        Provides the ServiceDiscoveryRes message with all its services.

        Currently, no filter based on service scope is applied since its string
        value is not standardized in any way. The only filter permitted for DIN SPEC is
        'EVCharging'.

        For payment options in DIN SPEC, only ExternalPayment is allowed.
        """
        auth_options: List[AuthEnum] = []
        if self.comm_session.selected_auth_option:
            # In case the EVCC resumes a paused charging session, the SECC
            # must only offer the auth option the EVCC selected previously
            if self.comm_session.selected_auth_option == AuthEnum.EIM_V2:
                auth_options.append(AuthEnum.EIM_V2)
        else:
            supported_auth_options = (
                self.comm_session.config.supported_auth_options_din_spec
            )
            if AuthEnum.EIM_V2 in supported_auth_options:
                auth_options.append(AuthEnum.EIM_V2)

        self.comm_session.offered_auth_options = auth_options

        energy_mode = (
            self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.DIN_SPEC_70121
            )[0]
        )  # noqa: E501

        service_details = ServiceDetails(
            service_id=ServiceID.CHARGING, service_category=ServiceCategory.CHARGING
        )
        charge_service = ChargeService(
            service_tag=service_details,
            free_service=self.comm_session.config.free_charging_service,
            energy_transfer_type=energy_mode,
        )

        service_discovery_res = ServiceDiscoveryRes(
            response_code=ResponseCode.OK,
            auth_option_list=AuthOptionList(auth_options=auth_options),
            charge_service=charge_service,
        )

        return service_discovery_res


class ServiceAndPaymentSelection(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [ServicePaymentSelectionReq])
        if not msg:
            return

        service_payment_selection_req: ServicePaymentSelectionReq = (
            msg.body.service_payment_selection_req
        )

        if service_payment_selection_req.selected_payment_option != AuthEnum.EIM_V2:
            return

        if (
            len(service_payment_selection_req.selected_service_list.selected_service)
            == 0
        ):
            return

        service_payment_selection_res: ServicePaymentSelectionRes = (
            ServicePaymentSelectionRes(response_code=ResponseCode.OK)
        )
        self.create_next_message(
            ContractAuthentication,
            service_payment_selection_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class ContractAuthentication(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [ContractAuthenticationReq])
        if not msg:
            return

        # The response contract_authentication_req is expected to be
        # empty and can be ignored. Move on to responding with
        # ContractAuthenticationRes

        evse_processing = self.comm_session.evse_controller.get_evse_processing_state()
        contract_authentication_res: ContractAuthenticationRes = (
            ContractAuthenticationRes(
                response_code=ResponseCode.OK, evse_processing=evse_processing
            )
        )

        next_state = (
            ChargeParameterDiscovery
            if evse_processing == EVSEProcessing.FINISHED
            else None
        )
        self.create_next_message(
            next_state,
            contract_authentication_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class ChargeParameterDiscovery(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [ChargeParameterDiscoveryReq])
        if not msg:
            return

        charge_parameter_discovery_req: ChargeParameterDiscoveryReq = (
            msg.body.charge_parameter_discovery_req
        )

        if charge_parameter_discovery_req.requested_energy_mode not in (
            self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.DIN_SPEC_70121
            )
        ):
            self.stop_state_machine(
                f"{charge_parameter_discovery_req.requested_energy_mode} not "
                f"offered as energy transfer mode",
                message,
                ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_MODE,
            )
            return

        self.comm_session.selected_energy_mode = (
            charge_parameter_discovery_req.requested_energy_mode
        )

        dc_evse_charge_params = (
            self.comm_session.evse_controller.get_dc_evse_charge_parameter()  # noqa
        )

        sa_schedule_list = (
            self.comm_session.evse_controller.get_sa_schedule_list_dinspec(None, 0)
        )

        charge_parameter_discovery_res: ChargeParameterDiscoveryRes = (
            ChargeParameterDiscoveryRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.FINISHED
                if sa_schedule_list
                else EVSEProcessing.ONGOING,
                sa_schedule_list=SAScheduleList(values=sa_schedule_list),
                dc_charge_parameter=dc_evse_charge_params,
            )
        )

        self.create_next_message(
            CableCheck,
            charge_parameter_discovery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class CableCheck(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [CableCheckReq])
        if not msg:
            return

        cable_check_req: CableCheckReq = msg.body.cable_check_req

        if not cable_check_req.dc_ev_status.ev_ready:
            return

        cable_check_res: CableCheckRes = CableCheckRes(
            response_code=ResponseCode.OK,
            dc_evse_status=self.comm_session.evse_controller.get_dc_evse_status(),
            evse_processing=(
                self.comm_session.evse_controller.get_evse_processing_state()
            ),
        )

        # [V2G-DC-418] Stay in CableCheck state until EVSEProcessing is complete.
        # Until EVSEProcessing is completed, EV will send identical
        # CableCheckReq message.
        next_state = (
            PreCharge
            if cable_check_res.evse_processing == EVSEProcessing.FINISHED
            else None
        )
        self.create_next_message(
            next_state,
            cable_check_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class PreCharge(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [PreChargeReq])
        if not msg:
            return

        pre_charge_req: PreChargeReq = msg.body.pre_charge_req
        if not pre_charge_req.dc_ev_status.ev_ready:
            return

        self.comm_session.evse_controller.set_ev_target_voltage(
            pre_charge_req.ev_target_voltage
        )
        self.comm_session.evse_controller.set_ev_target_current(
            pre_charge_req.ev_target_current
        )
        pre_charge_res: PreChargeRes = PreChargeRes(
            response_code=ResponseCode.OK,
            dc_evse_status=self.comm_session.evse_controller.get_dc_evse_status(),
            evse_present_voltage=(
                self.comm_session.evse_controller.get_evse_present_voltage()
            ),
        )
        self.create_next_message(
            PowerDelivery,
            pre_charge_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )


class PowerDelivery(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [PowerDeliveryReq])
        if not msg:
            return

        power_delivery_req: PowerDeliveryReq = msg.body.power_delivery_req

        power_delivery_res: PowerDeliveryRes = PowerDeliveryRes(
            response_code=ResponseCode.OK,
            dc_evse_status=self.comm_session.evse_controller.get_dc_evse_status(),
        )

        if power_delivery_req.ready_to_charge:
            self.create_next_message(
                CurrentDemand,
                power_delivery_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )
        else:
            self.create_next_message(
                WeldingDetection,
                power_delivery_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )


class CurrentDemand(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [CurrentDemandReq])
        if not msg:
            return

        current_demand_req: CurrentDemandReq = msg.body.current_demand_req

        current_demand_res: CurrentDemandRes = CurrentDemandRes(
            response_code=ResponseCode.OK,
            dc_evse_status=self.comm_session.evse_controller.get_dc_evse_status(),
            evse_present_voltage=(
                self.comm_session.evse_controller.get_evse_present_voltage()
            ),
            evse_present_current=(
                self.comm_session.evse_controller.get_evse_present_current()
            ),
            evse_current_limit_achieved=current_demand_req.charging_complete,
            evse_voltage_limit_achieved=(
                self.comm_session.evse_controller.is_evse_voltage_limit_achieved()
            ),
            evse_power_limit_achieved=(
                self.comm_session.evse_controller.is_evse_power_limit_achieved()
            ),
        )

        if current_demand_req.charging_complete:
            self.create_next_message(
                PowerDelivery,
                current_demand_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )
        else:
            self.create_next_message(
                None,
                current_demand_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )


class WeldingDetection(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expect_session_stop_req = False

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
        msg = self.check_msg_dinspec(
            message,
            [SessionStopReq, WeldingDetectionReq],
            self.expect_session_stop_req,
        )
        if not msg:
            return

        welding_detection_req: WeldingDetectionReq = msg.body.welding_detection_req

        session_stop_req: SessionStopReq = None
        if welding_detection_req is None:
            session_stop_req: SessionStopReq = msg.body.session_stop_req
            self.create_next_message(
                Terminate,
                SessionStopRes(response_code=ResponseCode.OK),
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )
        else:
            self.create_next_message(
                SessionStop,
                self.build_welding_detection_response(),
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.DIN_MSG_DEF,
            )

        if session_stop_req is None:
            return

    def build_welding_detection_response(self) -> WeldingDetectionRes:
        return WeldingDetectionRes(
            response_code=ResponseCode.OK,
            dc_evse_status=self.comm_session.evse_controller.get_dc_evse_status(),
            evse_present_voltage=(
                self.comm_session.evse_controller.get_evse_present_voltage()
            ),
        )


class SessionStop(StateSECC):
    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

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
        msg = self.check_msg_dinspec(message, [SessionStopReq])
        if not msg:
            return

        self.comm_session.stop_reason = StopNotification(
            True,
            "Communication session stopped successfully",
            self.comm_session.writer.get_extra_info("peername"),
        )

        self.create_next_message(
            Terminate,
            SessionStopRes(response_code=ResponseCode.OK),
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.DIN_MSG_DEF,
        )
