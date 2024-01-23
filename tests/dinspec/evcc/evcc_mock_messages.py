import time
from typing import List, Optional

from iso15118.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from iso15118.shared.messages.din_spec.body import (
    Body,
    ChargeParameterDiscoveryRes,
    ContractAuthenticationRes,
    CurrentDemandRes,
    PowerDeliveryRes,
    ServiceDiscoveryRes,
    ServicePaymentSelectionRes,
    SessionSetupRes,
    WeldingDetectionRes,
)
from iso15118.shared.messages.din_spec.datatypes import (
    AuthOptionList,
    ChargeService,
    IsolationLevel,
    PMaxScheduleEntry,
    PMaxScheduleEntryDetails,
    RelativeTimeInterval,
    ResponseCode,
    SAScheduleList,
    SAScheduleTupleEntry,
    ServiceCategory,
    ServiceDetails,
    ServiceID,
)
from iso15118.shared.messages.din_spec.header import MessageHeader
from iso15118.shared.messages.din_spec.msgdef import V2GMessage
from iso15118.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
)
from tests.tools import MOCK_SESSION_ID


def get_dc_evse_status():
    return DCEVSEStatus(
        evse_notification=EVSENotification.NONE,
        notification_max_delay=0,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def get_dc_evse_status_stop_charging():
    return DCEVSEStatus(
        evse_notification=EVSENotification.NONE,
        notification_max_delay=0,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_SHUTDOWN,
    )


def get_evse_present_voltage() -> PVEVSEPresentVoltage:
    return PVEVSEPresentVoltage(multiplier=0, value=230, unit="V")


def get_evse_present_current() -> PVEVSEPresentCurrent:
    return PVEVSEPresentCurrent(multiplier=0, value=10, unit="A")


def is_evse_current_limit_achieved() -> bool:
    return True


def is_evse_voltage_limit_achieved() -> bool:
    return True


def is_evse_power_limit_achieved() -> bool:
    return True


def get_dc_evse_charge_parameter() -> DCEVSEChargeParameter:
    """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""
    return DCEVSEChargeParameter(
        dc_evse_status=DCEVSEStatus(
            notification_max_delay=100,
            evse_notification=EVSENotification.NONE,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        ),
        evse_maximum_power_limit=PVEVSEMaxPowerLimit(multiplier=1, value=230, unit="W"),
        evse_maximum_current_limit=PVEVSEMaxCurrentLimit(
            multiplier=1, value=4, unit="A"
        ),
        evse_maximum_voltage_limit=PVEVSEMaxVoltageLimit(
            multiplier=1, value=4, unit="V"
        ),
        evse_minimum_current_limit=PVEVSEMinCurrentLimit(
            multiplier=1, value=2, unit="A"
        ),
        evse_minimum_voltage_limit=PVEVSEMinVoltageLimit(
            multiplier=1, value=4, unit="V"
        ),
        evse_peak_current_ripple=PVEVSEPeakCurrentRipple(
            multiplier=1, value=4, unit="A"
        ),
    )


def get_sa_schedule_list_dinspec() -> Optional[List[SAScheduleTupleEntry]]:
    sa_schedule_list: List[SAScheduleTupleEntry] = []
    entry_details = PMaxScheduleEntryDetails(
        p_max=200, time_interval=RelativeTimeInterval(start=0, duration=3600)
    )
    p_max_schedule_entries = [entry_details]
    pmax_schedule_entry = PMaxScheduleEntry(
        p_max_schedule_id=0, entry_details=p_max_schedule_entries
    )

    sa_schedule_tuple_entry = SAScheduleTupleEntry(
        sa_schedule_tuple_id=1,
        p_max_schedule=pmax_schedule_entry,
        sales_tariff=None,
    )
    sa_schedule_list.append(sa_schedule_tuple_entry)
    return sa_schedule_list


def get_failed_current_demand_acheived():
    current_demand_res: CurrentDemandRes = CurrentDemandRes(
        response_code=ResponseCode.FAILED_UNKNOWN_SESSION,
        dc_evse_status=get_dc_evse_status_stop_charging(),
        evse_present_voltage=get_evse_present_voltage(),
        evse_present_current=get_evse_present_current(),
        evse_current_limit_achieved=True,
        evse_voltage_limit_achieved=(is_evse_voltage_limit_achieved()),
        evse_power_limit_achieved=(is_evse_power_limit_achieved()),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(current_demand_res=current_demand_res),
    )


def get_service_discovery_message_payment_service_not_offered():
    service_details = ServiceDetails(
        service_id=ServiceID.CHARGING, service_category=ServiceCategory.CHARGING
    )
    charge_service = ChargeService(
        service_tag=service_details,
        free_service=True,
        energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
    )
    service_discovery_res = ServiceDiscoveryRes(
        response_code=ResponseCode.OK,
        auth_option_list=AuthOptionList(auth_options=[AuthEnum.PNC_V2]),
        charge_service=charge_service,
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_discovery_res=service_discovery_res),
    )


def get_service_discovery_message_charge_service_not_offered():
    service_details = ServiceDetails(
        service_id=ServiceID.CHARGING, service_category=ServiceCategory.CHARGING
    )
    charge_service = ChargeService(
        service_tag=service_details,
        free_service=True,
        energy_transfer_type=EnergyTransferModeEnum.AC_THREE_PHASE_CORE,
    )
    service_discovery_res = ServiceDiscoveryRes(
        response_code=ResponseCode.OK,
        auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
        charge_service=charge_service,
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_discovery_res=service_discovery_res),
    )


def get_service_discovery_message():
    service_details = ServiceDetails(
        service_id=ServiceID.CHARGING, service_category=ServiceCategory.CHARGING
    )
    charge_service = ChargeService(
        service_tag=service_details,
        free_service=True,
        energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
    )
    service_discovery_res = ServiceDiscoveryRes(
        response_code=ResponseCode.OK,
        auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
        charge_service=charge_service,
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_discovery_res=service_discovery_res),
    )


def get_current_demand_acheived():
    current_demand_res: CurrentDemandRes = CurrentDemandRes(
        response_code=ResponseCode.OK,
        dc_evse_status=get_dc_evse_status_stop_charging(),
        evse_present_voltage=get_evse_present_voltage(),
        evse_present_current=get_evse_present_current(),
        evse_current_limit_achieved=True,
        evse_voltage_limit_achieved=(is_evse_voltage_limit_achieved()),
        evse_power_limit_achieved=(is_evse_power_limit_achieved()),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(current_demand_res=current_demand_res),
    )


def get_v2g_message_current_demand_current_limit_not_achieved():
    current_demand_res = CurrentDemandRes(
        response_code=ResponseCode.OK,
        dc_evse_status=get_dc_evse_status(),
        evse_present_voltage=PVEVSEPresentVoltage(multiplier=0, value=230, unit="V"),
        evse_present_current=PVEVSEPresentCurrent(multiplier=0, value=10, unit="A"),
        evse_current_limit_achieved=False,
        evse_voltage_limit_achieved=False,
        evse_power_limit_achieved=False,
        evse_max_voltage_limit=PVEVSEMaxVoltageLimit(multiplier=0, value=600, unit="V"),
        evse_max_current_limit=PVEVSEMaxCurrentLimit(multiplier=0, value=300, unit="A"),
        evse_max_power_limit=PVEVSEMaxPowerLimit(multiplier=1, value=1000, unit="W"),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(current_demand_res=current_demand_res),
    )


def get_service_payment_selection_message():
    service_payment_selection_message = ServicePaymentSelectionRes(
        response_code=ResponseCode.OK
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_payment_selection_res=service_payment_selection_message),
    )


def get_service_payment_selection_fail_message():
    service_payment_selection_message = ServicePaymentSelectionRes(
        response_code=ResponseCode.FAILED_PAYMENT_SELECTION_INVALID
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_payment_selection_res=service_payment_selection_message),
    )


def get_contract_authentication_message():
    contract_authentication_message = ContractAuthenticationRes(
        response_code=ResponseCode.OK, evse_processing=EVSEProcessing.FINISHED
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(contract_authentication_res=contract_authentication_message),
    )


def get_contract_authentication_ongoing_message():
    contract_authentication_message = ContractAuthenticationRes(
        response_code=ResponseCode.OK, evse_processing=EVSEProcessing.ONGOING
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(contract_authentication_res=contract_authentication_message),
    )


def get_charge_parameter_discovery_on_going_message():
    dc_evse_charge_params = get_dc_evse_charge_parameter()  # noqa

    sa_schedule_list = get_sa_schedule_list_dinspec()

    charge_parameter_discovery_res: ChargeParameterDiscoveryRes = (
        ChargeParameterDiscoveryRes(
            response_code=ResponseCode.OK,
            evse_processing=EVSEProcessing.ONGOING,
            sa_schedule_list=SAScheduleList(values=sa_schedule_list),
            dc_charge_parameter=dc_evse_charge_params,
        )
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(charge_parameter_discovery_res=charge_parameter_discovery_res),
    )


def get_charge_parameter_discovery_message():
    dc_evse_charge_params = get_dc_evse_charge_parameter()  # noqa

    sa_schedule_list = get_sa_schedule_list_dinspec()

    charge_parameter_discovery_res: ChargeParameterDiscoveryRes = (
        ChargeParameterDiscoveryRes(
            response_code=ResponseCode.OK,
            evse_processing=EVSEProcessing.FINISHED,
            sa_schedule_list=SAScheduleList(values=sa_schedule_list),
            dc_charge_parameter=dc_evse_charge_params,
        )
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(charge_parameter_discovery_res=charge_parameter_discovery_res),
    )


def get_power_delivery_res_message():
    power_delivery_res: PowerDeliveryRes = PowerDeliveryRes(
        response_code=ResponseCode.OK,
        dc_evse_status=get_dc_evse_status(),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_res=power_delivery_res),
    )


def get_welding_detection_on_going_message():
    welding_detection: WeldingDetectionRes = WeldingDetectionRes(
        response_code=ResponseCode.OK,
        dc_evse_status=get_dc_evse_status(),
        evse_present_voltage=get_evse_present_voltage(),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(welding_detection_res=welding_detection),
    )


def get_session_setup_evseid_zero():
    session_setup: SessionSetupRes = SessionSetupRes(
        response_code=ResponseCode.OK, evse_id="00", datetime_now=time.time()
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(session_setup_res=session_setup),
    )
