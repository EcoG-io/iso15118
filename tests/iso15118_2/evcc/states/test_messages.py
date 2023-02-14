from iso15118.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from iso15118.shared.messages.enums import IsolationLevel
from iso15118.shared.messages.iso15118_2.body import (
    Body,
    CurrentDemandRes,
    PowerDeliveryRes,
)
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from tests.tools import MOCK_SESSION_ID


def get_dc_evse_status():
    return DCEVSEStatus(
        evse_notification=EVSENotification.NONE,
        notification_max_delay=0,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def get_v2g_message_current_demand_res():
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
        evse_id="UK123E1234",
        sa_schedule_tuple_id=123,
        receipt_required=False,
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(current_demand_res=current_demand_res),
    )


def get_v2g_message_current_demand_res_with_stop_charging():
    tmp = get_v2g_message_current_demand_res()
    tmp.body.current_demand_res.dc_evse_status.evse_notification = (
        EVSENotification.STOP_CHARGING
    )
    return tmp


def get_v2g_message_power_delivery_res():
    power_delivery_res = PowerDeliveryRes(
        response_code=ResponseCode.OK,
        dc_evse_status=get_dc_evse_status(),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_res=power_delivery_res),
    )
