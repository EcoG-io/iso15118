"""
This module contains the EVCC's States used to process the SECC's incoming
V2GMessage objects of the DIN SPEC 70121 protocol, from SessionSetupRes to
SessionStopRes.
"""

import logging
from typing import Union, List

from iso15118.shared.notifications import StopNotification

from iso15118.shared.states import Terminate

from iso15118.shared.messages.enums import EnergyTransferModeEnum, Protocol
from iso15118.evcc import evcc_settings
from iso15118.shared.messages.din_spec.datatypes import (
    ChargeService,
    SelectedService,
    SelectedServiceList,
    ResponseCode,
    EVSEProcessing,
    DCEVChargeParameter,
    DCEVStatus,
)

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.states.evcc_state import StateEVCC
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.din_spec.body import (
    SessionSetupRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServicePaymentSelectionReq,
    ServicePaymentSelectionRes,
    ContractAuthenticationReq,
    ContractAuthenticationRes,
    ChargeParameterDiscoveryReq,
    SessionStopRes,
    CableCheckReq,
    ChargeParameterDiscoveryRes,
    CableCheckRes,
    PreChargeReq,
    PreChargeRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    CurrentDemandReq,
    WeldingDetectionReq,
    CurrentDemandRes,
    WeldingDetectionRes,
    SessionStopReq,
)
from iso15118.shared.messages.enums import Namespace, AuthEnum
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.din_spec.timeouts import Timeouts

from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)


logger = logging.getLogger(__name__)


# ============================================================================
# |    EVCC STATES- DIN SPEC 70121                                           |
# ============================================================================


class SessionSetup(StateEVCC):
    """
    The DIN SPEC state in which the EVCC processes a SessionSetupRes from
    the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        # TODO: less the time used for waiting for and processing the
        #       SDPResponse and SupportedAppProtocolRes
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, SessionSetupRes)
        if not msg:
            return

        session_setup_res: SessionSetupRes = msg.body.session_setup_res

        self.comm_session.session_id = msg.header.session_id
        self.comm_session.evse_id = session_setup_res.evse_id

        # TODO Build ServiceDiscoveryReq() by including optional parameters.
        #  This would help test scope and category filtering at the SECC end

        self.create_next_message(
            ServiceDiscovery,
            ServiceDiscoveryReq(),
            Timeouts.SERVICE_DISCOVERY_REQ,
            Namespace.DIN_MSG_DEF,
        )


class ServiceDiscovery(StateEVCC):
    """
    The DIN SPEC state in which the EVCC processes a
    ServiceDiscoveryRes message from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, ServiceDiscoveryRes)
        if not msg:
            return

        service_discovery_res: ServiceDiscoveryRes = msg.body.service_discovery_res

        if not service_discovery_res.charge_service:
            self.stop_state_machine("ChargeService not offered")
            return

        self.select_auth_mode(service_discovery_res.auth_option_list.auth_options)
        self.select_services(service_discovery_res)
        self.select_energy_transfer_mode()

        charge_service: ChargeService = service_discovery_res.charge_service
        offered_energy_modes: List[EnergyTransferModeEnum] = [
            charge_service.energy_transfer_type
        ]

        if self.comm_session.selected_energy_mode not in offered_energy_modes:
            self.stop_state_machine(
                f"Offered energy transfer modes "
                f"{offered_energy_modes} not compatible with "
                f"{self.comm_session.selected_energy_mode}"
            )
            return

        selected_service_list = SelectedServiceList(
            selected_service=self.comm_session.selected_services
        )

        service_payment_selection = ServicePaymentSelectionReq(
            selected_payment_option=self.comm_session.selected_auth_option,
            selected_service_list=selected_service_list,
        )

        self.create_next_message(
            ServiceAndPaymentSelection,
            service_payment_selection,
            Timeouts.SERVICE_DISCOVERY_REQ,
            Namespace.DIN_MSG_DEF,
        )

    def select_energy_transfer_mode(self):
        """
        Check if an energy transfer mode was saved from a previously paused
        communication session and reuse for resumed session, otherwise request
        from EV controller.
        """
        if evcc_settings.RESUME_REQUESTED_ENERGY_MODE:
            logger.debug(
                "Reusing energy transfer mode "
                f"{evcc_settings.RESUME_REQUESTED_ENERGY_MODE} "
                "from previously paused session"
            )
            self.comm_session.selected_energy_mode = (
                evcc_settings.RESUME_REQUESTED_ENERGY_MODE
            )
            evcc_settings.RESUME_REQUESTED_ENERGY_MODE = None
        else:
            self.comm_session.selected_energy_mode = (
                self.comm_session.ev_controller.get_energy_transfer_mode(
                    Protocol.DIN_SPEC_70121
                )
            )

    def select_auth_mode(self, auth_option_list: List[AuthEnum]):
        """
        Check if an authorization mode (aka payment option) was
        saved from a previously paused communication session and reuse for
        resumed session, otherwise request from EV controller.
        """
        if evcc_settings.RESUME_SELECTED_AUTH_OPTION:
            logger.debug(
                "Reusing authorization option "
                f"{evcc_settings.RESUME_SELECTED_AUTH_OPTION} "
                "from previously paused session"
            )
            self.comm_session.selected_auth_option = (
                evcc_settings.RESUME_SELECTED_AUTH_OPTION
            )
            evcc_settings.RESUME_SELECTED_AUTH_OPTION = None
        else:
            # Choose External Identification Means (eim)
            # as the selected authorization option.
            if AuthEnum.EIM_V2 in auth_option_list:
                self.comm_session.selected_auth_option = AuthEnum.EIM_V2

    def select_services(self, service_discovery_res: ServiceDiscoveryRes):
        # Add the ChargeService as a selected service
        self.comm_session.selected_services.append(
            SelectedService(
                service_id=service_discovery_res.charge_service.service_tag.service_id
            )
        )


class ServiceAndPaymentSelection(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, ServicePaymentSelectionRes)
        if not msg:
            return

        service_payment_selection_res: ServicePaymentSelectionRes = (
            msg.body.service_payment_selection_res
        )

        if service_payment_selection_res.response_code != ResponseCode.OK:
            return

        contract_authentication_req: ContractAuthenticationReq = (
            ContractAuthenticationReq()
        )
        self.create_next_message(
            ContractAuthentication,
            contract_authentication_req,
            Timeouts.SERVICE_PAYMENT_SELECTION_REQ,
            Namespace.DIN_MSG_DEF,
        )


class ContractAuthentication(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, ContractAuthenticationRes)
        if not msg:
            return

        contract_authentication_res: ContractAuthenticationRes = (
            msg.body.contract_authentication_res
        )

        if contract_authentication_res.response_code != ResponseCode.OK:
            return

        # There are two transitions possible in ContractAuthentication state:
        # 1. We stay in the same state until EVSE processing is complete.
        # ie, EVSE returns EVSEProcessing.ONGOING response
        # 2. Move on to next state: ChargeParameterDiscoveryReq
        if contract_authentication_res.evse_processing == EVSEProcessing.ONGOING:
            self.create_next_message(
                None,
                ContractAuthentication(),
                Timeouts.SERVICE_PAYMENT_SELECTION_REQ,
                Namespace.DIN_MSG_DEF,
            )
        elif contract_authentication_res.evse_processing == EVSEProcessing.FINISHED:
            charge_parameter_discovery_req: ChargeParameterDiscoveryReq = (
                self.build_charge_parameter_discovery_req()
            )

            self.create_next_message(
                ChargeParameterDiscovery,
                charge_parameter_discovery_req,
                Timeouts.CHARGE_PARAMETER_DISCOVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )

    def build_charge_parameter_discovery_req(self) -> ChargeParameterDiscoveryReq:
        dc_ev_status: DCEVStatus = self.comm_session.ev_controller.get_dc_ev_status()
        max_current_limit = self.comm_session.ev_controller.get_dc_max_current_limit()
        max_voltage_limit = self.comm_session.ev_controller.get_dc_max_voltage_limit()
        dc_charge_parameter: DCEVChargeParameter = DCEVChargeParameter(
            dc_ev_status=dc_ev_status,
            ev_maximum_current_limit=max_current_limit,
            ev_maximum_voltage_limit=max_voltage_limit,
        )
        return ChargeParameterDiscoveryReq(
            requested_energy_mode=EnergyTransferModeEnum.DC_CORE,
            dc_ev_charge_parameter=dc_charge_parameter,
        )


class ChargeParameterDiscovery(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, ChargeParameterDiscoveryRes)
        if not msg:
            return

        charge_parameter_discovery_res: ChargeParameterDiscoveryRes = (
            msg.body.charge_parameter_discovery_res
        )
        # TODO: USE THE RETURNED PARAMETERS.
        if charge_parameter_discovery_res.response_code != ResponseCode.OK:
            return

        cable_check_req = self.build_cable_check_req()
        self.create_next_message(
            CableCheck,
            cable_check_req,
            Timeouts.CABLE_CHECK_REQ,
            Namespace.DIN_MSG_DEF,
        )

    def build_cable_check_req(self) -> CableCheckReq:
        cable_check_req = CableCheckReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status()
        )
        return cable_check_req


class CableCheck(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        # TODO: less the time used for waiting for and processing the
        #       SDPRequest and SupportedAppProtocolReq
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, CableCheckRes)
        if not msg:
            return

        cable_check_res: CableCheckRes = msg.body.cable_check_res
        # TODO: USE THE RETURNED PARAMETERS.
        if cable_check_res.response_code != ResponseCode.OK:
            return

        pre_charge_req: PreChargeReq = self.build_pre_charge_req()
        self.create_next_message(
            PreCharge,
            pre_charge_req,
            Timeouts.PRE_CHARGE_REQ,
            Namespace.DIN_MSG_DEF,
        )

    def build_pre_charge_req(self) -> PreChargeReq:
        pre_charge_req = PreChargeReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status(),
            ev_target_voltage=self.comm_session.ev_controller.get_dc_target_voltage(),
            ev_target_current=self.comm_session.ev_controller.get_dc_target_current(),
        )
        return pre_charge_req


class PreCharge(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, PreChargeRes)
        if not msg:
            return

        pre_charge_res: PreChargeRes = msg.body.pre_charge_res
        # TODO: USE THE RETURNED PARAMETERS.
        if pre_charge_res.response_code != ResponseCode.OK:
            return

        # if pre_charge_res.evse_present_voltage < self.comm_session.ev_controller.get_param_dc_target_voltage():
        if False:
            pre_charge_req: PreChargeReq = self.build_pre_charge_req()
            self.create_next_message(
                None,
                pre_charge_req,
                Timeouts.PRE_CHARGE_REQ,
                Namespace.DIN_MSG_DEF,
            )
        else:
            power_delivery_req: PowerDeliveryReq = self.build_power_delivery_req()
            self.create_next_message(
                PowerDelivery,
                power_delivery_req,
                Timeouts.POWER_DELIVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )

    def build_pre_charge_req(self) -> PreChargeReq:
        pre_charge_req = PreChargeReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status(),
            ev_target_voltage=self.comm_session.ev_controller.get_dc_target_voltage(),
            ev_target_current=self.comm_session.ev_controller.get_dc_target_current(),
        )
        return pre_charge_req

    def build_power_delivery_req(self) -> PowerDeliveryReq:
        power_delivery_req = PowerDeliveryReq(
            ready_to_charge=self.comm_session.ev_controller.ready_to_charge(),
            dc_ev_power_delivery_parameter=self.comm_session.ev_controller.get_dc_ev_power_delivery_parameter(),
        )
        return power_delivery_req


class PowerDelivery(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, PowerDeliveryRes)
        if not msg:
            return

        power_delivery_res: PowerDeliveryRes = msg.body.power_delivery_res
        # TODO: USE THE RETURNED PARAMETERS.
        if power_delivery_res.response_code != ResponseCode.OK:
            return

        if self.comm_session.ev_controller.continue_charging():
            self.create_next_message(
                CurrentDemand,
                self.build_current_demand_req(),
                Timeouts.POWER_DELIVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )
        else:
            self.create_next_message(
                WeldingDetection,
                self.build_welding_detection_req(),
                Timeouts.POWER_DELIVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )

    def build_current_demand_req(self):
        current_demand_req: CurrentDemandReq = CurrentDemandReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status(),
            ev_target_current=self.comm_session.ev_controller.get_dc_target_current(),
            charging_complete=False
            if self.comm_session.ev_controller.continue_charging()
            else True,
            ev_target_voltage=self.comm_session.ev_controller.get_dc_target_voltage(),
        )
        return current_demand_req

    def build_welding_detection_req(self):
        welding_detection_req: WeldingDetectionReq = WeldingDetectionReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status()
        )
        return welding_detection_req


class CurrentDemand(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, CurrentDemandRes)
        if not msg:
            return

        current_demand_res: CurrentDemandRes = msg.body.current_demand_res
        # TODO: USE THE RETURNED PARAMETERS.
        if current_demand_res.response_code != ResponseCode.OK:
            return

        if current_demand_res.evse_current_limit_achieved:
            self.create_next_message(
                PowerDelivery,
                self.build_power_delivery_req(),
                Timeouts.POWER_DELIVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )
        else:
            self.create_next_message(
                None,
                self.build_current_demand_req(),
                Timeouts.POWER_DELIVERY_REQ,
                Namespace.DIN_MSG_DEF,
            )

    def build_power_delivery_req(self) -> PowerDeliveryReq:
        power_delivery_req = PowerDeliveryReq(
            ready_to_charge=self.comm_session.ev_controller.ready_to_charge(),
            dc_ev_power_delivery_parameter=self.comm_session.ev_controller.get_dc_ev_power_delivery_parameter(),
        )
        return power_delivery_req

    def build_current_demand_req(self):
        current_demand_req: CurrentDemandReq = CurrentDemandReq(
            dc_ev_status=self.comm_session.ev_controller.get_dc_ev_status(),
            ev_target_current=self.comm_session.ev_controller.get_dc_target_current(),
            charging_complete=False
            if self.comm_session.ev_controller.continue_charging()
            else True,
            ev_target_voltage=self.comm_session.ev_controller.get_dc_target_voltage(),
        )
        return current_demand_req


class WeldingDetection(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, WeldingDetectionRes)
        if not msg:
            return

        welding_detection_res: WeldingDetectionRes = msg.body.welding_detection_res
        # TODO: USE THE RETURNED PARAMETERS.
        if welding_detection_res.response_code != ResponseCode.OK:
            return

        self.create_next_message(
            SessionStop,
            SessionStopReq(),
            Timeouts.POWER_DELIVERY_REQ,
            Namespace.DIN_MSG_DEF,
        )


class SessionStop(StateEVCC):
    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_SEQUENCE_PERFORMANCE_TIME)

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
        msg = self.check_msg_din_spec(message, SessionStopRes)
        if not msg:
            return

        # if self.comm_session.charging_session_stop == ChargingSession.TERMINATE:
        #     stopped = "terminated"
        # else:
        #     stopped = "paused"

        self.comm_session.stop_reason = StopNotification(
            True,
            f"Communication session stopped successfully",
            self.comm_session.writer.get_extra_info("peername"),
        )

        self.next_state = Terminate

        return
