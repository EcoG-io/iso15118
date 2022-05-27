from unittest.mock import Mock, patch

import pytest

from iso15118.secc.states.iso15118_2_states import (
    Authorization,
    ChargeParameterDiscovery,
    CurrentDemand,
    PowerDelivery,
    Terminate,
    WeldingDetection,
)
from iso15118.secc.states.secc_state import StateSECC
from iso15118.shared.messages.enums import AuthEnum, AuthorizationStatus
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

    @pytest.mark.parametrize(
        "is_authorized_return_value, expected_next_state",
        [
            (AuthorizationStatus.ACCEPTED, ChargeParameterDiscovery),
            (AuthorizationStatus.ONGOING, Authorization),
            pytest.param(
                AuthorizationStatus.REJECTED,
                Terminate,
                marks=pytest.mark.xfail(
                    reason="REJECTED handling not implemented yet; "
                    "see GitHub issue #54",
                ),
            ),
        ],
    )
    async def test_authorization_next_state_on_authorization_request(
        self,
        is_authorized_return_value: AuthorizationStatus,
        expected_next_state: StateSECC,
    ):
        self.comm_session.selected_auth_option = AuthEnum.EIM
        mock_is_authorized = Mock(return_value=is_authorized_return_value)
        self.comm_session.evse_controller.is_authorized = mock_is_authorized
        authorization = Authorization(self.comm_session)
        authorization.process_message(message=get_dummy_v2g_message_authorization_req())
        assert authorization.next_state == expected_next_state
