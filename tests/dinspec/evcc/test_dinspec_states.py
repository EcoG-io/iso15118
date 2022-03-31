import time
from unittest.mock import Mock

import pytest as pytest
from iso15118.shared.states import Terminate

from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.states.din_spec_states import CurrentDemand, ServiceDiscovery, \
    ServicePaymentSelection, PowerDelivery, ContractAuthentication,\
    ChargeParameterDiscovery, CableCheck

from iso15118.shared.messages.enums import Protocol, EnergyTransferModeEnum, AuthEnum
from iso15118.shared.notifications import StopNotification

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession

from iso15118.shared.exificient_exi_codec import ExificientEXICodec

from iso15118.shared.exi_codec import EXI
from tests.dinspec.evcc.evcc_mock_messages import \
    get_v2g_message_current_demand_current_limit_not_achieved, \
    get_service_discovery_message_payment_service_not_offered, \
    get_service_discovery_message_charge_service_not_offered, \
    get_service_discovery_message, get_current_demand_acheived, \
    get_contract_authentication_message, \
    get_service_payment_selection_message, get_service_payment_selection_fail_message,\
    get_contract_authentication_ongoing_message, \
    get_charge_parameter_discovery_message,\
    get_charge_parameter_discovery_on_going_message


class MockWriter:
    def get_extra_info(self, query_string : str):
        return "not supported"


@pytest.fixture
def comm_session_mock():
    comm_session_mock = Mock(spec=EVCCCommunicationSession)
    comm_session_mock.session_id = "F9F9EE8505F55838"
    comm_session_mock.stop_reason = StopNotification(
        False, "pytest"
    )
    comm_session_mock.ev_controller = SimEVController()
    comm_session_mock.protocol = Protocol.DIN_SPEC_70121
    comm_session_mock.selected_schedule = 1
    comm_session_mock.selected_services = []
    comm_session_mock.selected_energy_mode = EnergyTransferModeEnum.DC_CORE
    comm_session_mock.selected_auth_option = AuthEnum.EIM_V2
    comm_session_mock.writer = MockWriter()
    comm_session_mock.ongoing_timer: float = -1
    EXI().set_exi_codec(ExificientEXICodec())
    return comm_session_mock


@pytest.fixture
def mock_sleep(monkeypatch):
    def sleep(seconds):
        pass
    monkeypatch.setattr(time, 'sleep', sleep)


def test_service_discovery_payment_service_not_offered(comm_session_mock):
    service_discovery = ServiceDiscovery(comm_session_mock)
    service_discovery.process_message(message=get_service_discovery_message_payment_service_not_offered())
    assert service_discovery.next_state is Terminate


def test_service_discovery_charge_service_not_offered(comm_session_mock):
    service_discovery = ServiceDiscovery(comm_session_mock)
    service_discovery.process_message(message=get_service_discovery_message_charge_service_not_offered())
    assert service_discovery.next_state is Terminate


def test_service_discovery_to_service_payment_selection(comm_session_mock):
    service_discovery = ServiceDiscovery(comm_session_mock)
    service_discovery.process_message(message=get_service_discovery_message())
    assert service_discovery.next_state is ServicePaymentSelection


def test_service_payment_selection_fail(comm_session_mock):
    service_payment_selection = ServicePaymentSelection(comm_session_mock)
    service_payment_selection.process_message(message=get_service_payment_selection_fail_message())
    assert service_payment_selection.next_state is Terminate


def test_service_payment_selection_to_contract_authentication(comm_session_mock):
    service_payment_selection = ServicePaymentSelection(comm_session_mock)
    service_payment_selection.process_message(message=get_service_payment_selection_message())
    assert service_payment_selection.next_state is ContractAuthentication


def test_contract_authentication_on_going(comm_session_mock):
    contract_authentication = ContractAuthentication(comm_session_mock)
    contract_authentication.process_message(message=get_contract_authentication_ongoing_message())
    assert contract_authentication.next_state is None


def test_contract_authentication_to_charge_parameter_discovery(comm_session_mock):
    contract_authentication = ContractAuthentication(comm_session_mock)
    contract_authentication.process_message(message=get_contract_authentication_message())
    assert contract_authentication.next_state is ChargeParameterDiscovery


def test_current_demand_req_to_power_delivery_req(comm_session_mock):
    current_demand = CurrentDemand(comm_session_mock)
    current_demand.process_message(message=get_current_demand_acheived())
    assert current_demand.next_state is PowerDelivery


def test_current_demand_to_current_demand(comm_session_mock):
    current_demand = CurrentDemand(comm_session_mock)
    current_demand.process_message(message=get_v2g_message_current_demand_current_limit_not_achieved())
    assert current_demand.next_state is None


def test_charge_parameter_discovery_to_cable_check(comm_session_mock):
    charge_parameter_discovery = ChargeParameterDiscovery(comm_session_mock)
    charge_parameter_discovery.process_message(message=get_charge_parameter_discovery_message())
    assert charge_parameter_discovery.next_state is CableCheck


def test_charge_parameter_discovery_timeout(comm_session_mock):
    charge_parameter_discovery = ChargeParameterDiscovery(comm_session_mock)
    charge_parameter_discovery.process_message(message=get_charge_parameter_discovery_on_going_message())
    charge_parameter_discovery.process_message(message=get_charge_parameter_discovery_on_going_message())
    assert charge_parameter_discovery.next_state is None
    time.sleep(60)
    charge_parameter_discovery.process_message(message=get_charge_parameter_discovery_on_going_message())
    assert charge_parameter_discovery.next_state is Terminate


def cable_check_req_to_pre_charge(comm_session_mock):
    pass


def cable_check_req_to_cable_check_req(comm_session_mock):
    pass


def pre_charge_to_pre_charge(comm_session_mock):
    pass


def pre_charge_to_power_delivery(comm_session_mock):
    pass


def power_delivery_to_current_demand(comm_session_mock):
    pass


def current_demand_to_terminate(comm_session_mock):
    pass


def current_demand_to_current_demand(comm_session_mock):
    pass


def current_demand_to_power_delivery(comm_session_mock):
    pass


def test_power_delivery_to_welding_detection(comm_session_mock):
    pass


def test_power_delivery_to_session_stop(comm_session_mock):
    pass


def test_welding_detection_to_session_stop(comm_session_mock):
    pass
