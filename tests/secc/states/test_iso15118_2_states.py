from unittest.mock import Mock, patch

import pytest

from iso15118.secc.states.iso15118_2_states import (
    Authorization,
    ChargeParameterDiscovery,
    CurrentDemand,
    PowerDelivery,
    WeldingDetection,
)
from iso15118.shared.messages.enums import AuthEnum
from tests.secc.states.test_messages import (
    get_dummy_v2g_message_authorization_req,
    get_dummy_v2g_message_welding_detection_req,
    get_v2g_message_power_delivery_req,
)


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value="\x01"))
@pytest.mark.asyncio
class TestEvScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self, comm_secc_session_mock):
        self.comm_session = comm_secc_session_mock

    async def test_current_demand_to_power_delivery_when_power_delivery_received(
        self,
    ):
        current_demand = CurrentDemand(self.comm_session)
        current_demand.expecting_current_demand_req = False
        current_demand.process_message(message=get_v2g_message_power_delivery_req())
        assert isinstance(self.comm_session.current_state, PowerDelivery)

    async def test_power_delivery_to_welding_detection_when_welding_detection_received(
        self,
    ):
        # V2G2-601 (to WeldingDetection)
        power_delivery = PowerDelivery(self.comm_session)
        power_delivery.expecting_power_delivery_req = False
        power_delivery.process_message(
            message=get_dummy_v2g_message_welding_detection_req()
        )
        assert isinstance(self.comm_session.current_state, WeldingDetection)

    async def test_welding_detection_to_session_stop_when_session_stop_received(
        self,
    ):
        pass
        # V2G2-570

    async def test_authorization_to_parameter_discovery_when_authorization_accepted(
        self,
    ):
        self.comm_session.selected_auth_option = AuthEnum.EIM
        authorization = Authorization(self.comm_session)
        authorization.process_message(message=get_dummy_v2g_message_authorization_req())
        assert isinstance(self.comm_session.current_state, ChargeParameterDiscovery)

    async def test_authorization_to_authorization_when_authorization_ongoing(self):
        assert False

    async def test_authorization_to_authorization_when_authorization_rejected(self):
        assert False
