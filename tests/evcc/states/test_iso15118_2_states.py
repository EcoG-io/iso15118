import copy
from unittest.mock import Mock

import pytest

from evcc.states.test_messages import get_v2g_message_current_demand_res, \
    get_v2g_message_current_demand_res_with_stop_charging, get_v2g_message_power_delivery_res
from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.states.iso15118_2_states import CurrentDemand, PowerDelivery, WeldingDetection
from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.datatypes import ChargingSession, EnergyTransferModeEnum
from iso15118.shared.notifications import StopNotification



@pytest.fixture
def comm_session_mock():
    comm_session_mock = Mock(spec=EVCCCommunicationSession)
    comm_session_mock.session_id = "F9F9EE8505F55838"
    comm_session_mock.stop_reason = StopNotification(
        False, "pytest"
    )
    comm_session_mock.ev_controller = SimEVController()
    comm_session_mock.protocol = Protocol.UNKNOWN
    comm_session_mock.selected_schedule = 1
    return comm_session_mock


def test_current_demand_to_current_demand(comm_session_mock):
    #  according V2G2-531
    current_demand = CurrentDemand(comm_session_mock)
    current_demand.process_message(message=get_v2g_message_current_demand_res())
    assert current_demand.next_state == CurrentDemand


def test_current_demand_to_power_delivery__when__evse_notification_is_stop_charging(comm_session_mock):
    # according V2G2-679 (EVSENotification = EVSENotification)
    # as well in states chargeParameterDiscoveryRes, PowerDeliveryREs, MeteringReceiptRes,
    # PrechargeRes, currentDemandRes, WeldingDetectionREs ??
    current_demand = CurrentDemand(comm_session_mock)
    current_demand.process_message(message=get_v2g_message_current_demand_res_with_stop_charging())
    assert current_demand.next_state == PowerDelivery


def test_current_demand_to_power_delivery__when__stopped_by_ev(comm_session_mock):
    # V2G2-527
    pass



def test_power_delivery_to_welding_detection__when__charge_progress_is_stop(comm_session_mock):
    # V2G2-533
    power_delivery = PowerDelivery(comm_session_mock)
    comm_session_mock.charging_session_stop = ChargingSession.TERMINATE
    comm_session_mock.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
    power_delivery.process_message(message=get_v2g_message_power_delivery_res())
    assert power_delivery.next_state == WeldingDetection
