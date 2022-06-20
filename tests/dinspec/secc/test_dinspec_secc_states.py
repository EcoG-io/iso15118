from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.states.din_spec_states import CurrentDemand, PowerDelivery
from iso15118.shared.messages.enums import EnergyTransferModeEnum, Protocol
from iso15118.shared.notifications import StopNotification


class MockWriter:
    def get_extra_info(self, query_string: str):
        return "not supported"


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvseScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self):
        self.comm_session = Mock(spec=SECCCommunicationSession)
        self.comm_session.session_id = "F9F9EE8505F55838"
        # comm_session.offered_schedules = get_sa_schedule_list()
        self.comm_session.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
        self.comm_session.selected_charging_type_is_ac = False
        self.comm_session.stop_reason = StopNotification(False, "pytest")
        self.comm_session.evse_controller = SimEVSEController()
        self.comm_session.protocol = Protocol.UNKNOWN
        self.comm_session.writer = MockWriter()

    async def test_sap_to_billing(self):
        pass

    async def test_setup_charging(self):
        pass

    async def test_charging(self, current_on_going_req):
        current_demand: CurrentDemand = CurrentDemand(self.comm_session)
        await current_demand.process_message(current_on_going_req)
        assert current_demand.next_state is None
        await current_demand.process_message(current_on_going_req)
        assert current_demand.next_state is None

    async def test_charging_finish(self, current_on_going_req):
        current_demand: CurrentDemand = CurrentDemand(self.comm_session)
        await current_demand.process_message(current_on_going_req)
        assert current_demand.next_state is None
        await current_demand.process_message(current_on_going_req)
        assert current_demand.next_state is None

    async def test_finalise_charging(self):
        pass

    async def test_power_delivery_req_set_hlc_charging(
        self,
        power_delivery_req_charge_start,
        power_delivery_req_charge_stop,
    ):
        power_delivery = PowerDelivery(self.comm_session)
        self.comm_session.evse_controller.set_hlc_charging = AsyncMock()

        # hlc is set to True
        await power_delivery.process_message(message=power_delivery_req_charge_start)

        self.comm_session.evse_controller.set_hlc_charging.assert_called_with(True)

        # hlc is set to False
        await power_delivery.process_message(message=power_delivery_req_charge_stop)

        self.comm_session.evse_controller.set_hlc_charging.assert_called_with(False)
