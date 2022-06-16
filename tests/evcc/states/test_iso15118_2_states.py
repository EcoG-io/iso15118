from unittest.mock import Mock, patch

import pytest

from iso15118.evcc.states.iso15118_2_states import (
    CurrentDemand,
    PowerDelivery,
    WeldingDetection,
)
from iso15118.shared.messages.iso15118_2.datatypes import ChargingSession
from iso15118.shared.notifications import StopNotification
from tests.evcc.states.test_messages import (
    get_v2g_message_current_demand_res,
    get_v2g_message_current_demand_res_with_stop_charging,
    get_v2g_message_power_delivery_res,
)


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self, comm_evcc_session_mock):
        self.comm_session = comm_evcc_session_mock

    async def test_current_demand_to_current_demand(self):
        #  according V2G2-531
        current_demand = CurrentDemand(self.comm_session)
        await current_demand.process_message(
            message=get_v2g_message_current_demand_res()
        )
        assert current_demand.next_state == CurrentDemand

    async def test_current_demand_power_delivery_when_notification_is_stop_charging(
        self,
    ):
        # according V2G2-679 (EVSENotification = EVSENotification)
        # as well in states chargeParameterDiscoveryRes, PowerDeliveryREs,
        # MeteringReceiptRes, PrechargeRes, currentDemandRes, WeldingDetectionREs ??
        current_demand = CurrentDemand(self.comm_session)
        await current_demand.process_message(
            message=get_v2g_message_current_demand_res_with_stop_charging(),
        )
        assert current_demand.next_state == PowerDelivery

    async def test_current_demand_to_power_delivery_when_stopped_by_ev(self):
        # V2G2-527
        pass

    async def test_power_delivery_to_welding_detection_when_charge_progress_is_stop(
        self,
    ):
        # V2G2-533
        self.comm_session.stop_reason = StopNotification(True, "pytest")
        power_delivery = PowerDelivery(self.comm_session)
        self.comm_session.charging_session_stop_v2 = ChargingSession.TERMINATE
        await power_delivery.process_message(
            message=get_v2g_message_power_delivery_res()
        )
        assert power_delivery.next_state == WeldingDetection
