from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.ev_data import EVSessionContext15118
from iso15118.secc.controller.evse_data import (
    DCLimits,
    EVSEDataContext,
    EVSERatedLimits,
    EVSESessionContext, DCCLLimits,
)
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
        self.comm_session.evse_id = "UK123E1234"
        self.comm_session.writer = MockWriter()
        self.comm_session.ev_session_context = EVSessionContext15118()
        self.comm_session.evse_controller.evse_data_context = self.get_evse_data()

    def get_evse_data(self) -> EVSEDataContext:
        dc_limits = DCLimits(
            evse_max_charge_power=10,
            evse_min_charge_power=10,
            evse_max_charge_current=10,
            evse_min_charge_current=10,
            evse_max_voltage=10,
            evse_min_voltage=10,
            evse_power_ramp_limit=10,
            # 15118-20 DC BPT
            evse_max_discharge_power=10,
            evse_min_discharge_power=10,
            evse_max_discharge_current=10,
            evse_min_discharge_current=10,
            # 15118-2 DC, DINSPEC
            evse_maximum_current_limit=10,
            evse_maximum_power_limit=10,
            evse_maximum_voltage_limit=10,
            evse_minimum_current_limit=10,
            evse_minimum_voltage_limit=10,
            evse_current_regulation_tolerance=10,
            evse_peak_current_ripple=10,
            evse_energy_to_be_delivered=10,
        )
        dc_cl_limits = DCCLLimits(
            # Optional in 15118-20 DC CL (Scheduled)
            evse_max_charge_power=10,
            evse_min_charge_power=10,
            evse_max_charge_current=10,
            evse_max_voltage=10,

            # Optional and present in 15118-20 DC BPT CL (Scheduled)
            evse_max_discharge_power=10,
            evse_min_discharge_power=10,
            evse_max_discharge_current=10,
            evse_min_voltage=10,
        )
        rated_limits: EVSERatedLimits = EVSERatedLimits(
            ac_limits=None, dc_limits=dc_limits
        )
        session_context: EVSESessionContext = EVSESessionContext(
            ac_limits=None, dc_limits=dc_cl_limits
        )

        return EVSEDataContext(
            rated_limits=rated_limits, session_context=session_context
        )

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
