from unittest.mock import Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.states.din_spec_states import CurrentDemand
from iso15118.shared.messages.enums import EnergyTransferModeEnum, Protocol
from iso15118.shared.notifications import StopNotification
from tests.dinspec.secc.secc_mock_messages import get_current_on_going_req


class MockWriter:
    def get_extra_info(self, query_string: str):
        return "not supported"


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvseScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self):
        self.comm_session_mock = Mock(spec=SECCCommunicationSession)
        self.comm_session_mock.session_id = "F9F9EE8505F55838"
        # comm_session_mock.offered_schedules = get_sa_schedule_list()
        self.comm_session_mock.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
        self.comm_session_mock.selected_charging_type_is_ac = False
        self.comm_session_mock.stop_reason = StopNotification(False, "pytest")
        self.comm_session_mock.evse_controller = SimEVSEController()
        self.comm_session_mock.protocol = Protocol.UNKNOWN
        self.comm_session_mock.writer = MockWriter()

    async def test_sap_to_billing(self):
        pass

    async def test_setup_charging(self):
        pass

    async def test_charging(self):
        current_demand: CurrentDemand = CurrentDemand(self.comm_session_mock)
        await current_demand.process_message(get_current_on_going_req())
        assert current_demand.next_state is None
        await current_demand.process_message(get_current_on_going_req())
        assert current_demand.next_state is None

    async def test_charging_finish(self):
        current_demand: CurrentDemand = CurrentDemand(self.comm_session_mock)
        await current_demand.process_message(get_current_on_going_req())
        assert current_demand.next_state is None
        await current_demand.process_message(get_current_on_going_req())
        assert current_demand.next_state is None

    async def test_finalise_charging(self):
        pass
