from unittest.mock import Mock

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.states.iso15118_2_states import CurrentDemand
from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.body import CurrentDemandRes, Body
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode, PVEVSEPresentCurrent, PVEVSEMaxVoltageLimit, \
    PVEVSEMaxCurrentLimit, PVEVSEMaxPowerLimit, PVEVSEPresentVoltage, DCEVSEStatus, EVSENotification, IsolationLevel, \
    DCEVSEStatusCode
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from iso15118.shared.notifications import StopNotification


def test_process_message():

    dc_evse_status = DCEVSEStatus(
            evse_notification=EVSENotification.NONE,
            notification_max_delay=0,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        )
    current_demand_res = CurrentDemandRes(
        response_code=ResponseCode.OK,
        dc_evse_status=dc_evse_status,
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
    test_message = V2GMessage(
        header=MessageHeader(session_id="F9F9EE8505F55838"),
        body=Body(current_demand_res=current_demand_res),
    )

    comm_session_mock = Mock(spec=EVCCCommunicationSession)
    comm_session_mock.session_id = "F9F9EE8505F55838"
    comm_session_mock.stop_reason = StopNotification(
            False, "pytest"
        )
    comm_session_mock.ev_controller = SimEVController()
    comm_session_mock.protocol = Protocol.UNKNOWN

    current_demand = CurrentDemand(comm_session_mock)

    current_demand.process_message(message=test_message)

    assert current_demand.next_state == CurrentDemand
