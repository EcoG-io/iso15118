from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.interface import AuthorizationResponse
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.failed_responses import init_failed_responses_iso_v20
from iso15118.secc.states.iso15118_20_states import (
    ACChargeLoop,
    Authorization,
    PowerDelivery,
    ServiceDetail,
)
from iso15118.shared.messages.enums import (
    AuthEnum,
    AuthorizationStatus,
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    Protocol,
    ServiceV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ChargeProgress,
    MatchedService,
    SelectedEnergyService,
    Service,
    ServiceList,
)
from iso15118.shared.messages.iso15118_20.common_types import Processing, ResponseCode
from iso15118.shared.notifications import StopNotification
from iso15118.shared.states import Terminate
from tests.dinspec.secc.test_dinspec_secc_states import MockWriter
from tests.iso15118_20.secc.test_messages import (
    get_power_delivery_req,
    get_v2g_message_authorization_req,
    get_v2g_message_service_detail_req,
)


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self):
        self.comm_session = Mock(spec=SECCCommunicationSession)
        self.comm_session.session_id = "F9F9EE8505F55838"
        self.comm_session.selected_energy_mode = (
            EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        )
        self.comm_session.selected_charging_type_is_ac = False
        self.comm_session.stop_reason = StopNotification(False, "pytest")
        self.comm_session.protocol = Protocol.ISO_15118_20_AC
        self.comm_session.writer = MockWriter()
        self.comm_session.failed_responses_isov20 = init_failed_responses_iso_v20()
        self.comm_session.evse_controller = SimEVSEController()

    @pytest.mark.parametrize(
        "service_id_input, response_code",
        [
            (1, ResponseCode.OK),
            (5, ResponseCode.OK),
            (2, ResponseCode.FAILED_SERVICE_ID_INVALID),
        ],
    )
    async def test_service_detail_service_id_is_in_offered_list(
        self, service_id_input, response_code
    ):
        # [V2G20-464] The message "ServiceDetailRes" shall contain the
        # ResponseCode "FAILED_ServiceIDInvalid" if the ServiceID contained
        # in the ServiceDetailReq message was not part of the offered
        # EnergyTransferServiceList or VASList during ServiceDiscovery.

        self.comm_session.matched_services_v20 = []
        self.comm_session.evse_controller = await SimEVSEController.create()
        service_ids = [1, 5]
        offered_energy_services: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            offered_energy_services.services.append(
                Service(service_id=service_id, free_service=False)
            )

        for energy_service in offered_energy_services.services:
            self.comm_session.matched_services_v20.append(
                MatchedService(
                    service=ServiceV20.get_by_id(energy_service.service_id),
                    is_energy_service=True,
                    is_free=energy_service.free_service,
                    # Parameter sets are available with ServiceDetailRes
                    parameter_sets=[],
                )
            )

        service_details = ServiceDetail(self.comm_session)
        await service_details.process_message(
            message=get_v2g_message_service_detail_req(service_id_input)
        )
        assert service_details.message.response_code is response_code
        assert isinstance(self.comm_session.current_state, ServiceDetail)

    @pytest.mark.parametrize(
        "is_authorized_response, auth_mode, next_req_is_auth_req",
        [
            (
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                AuthEnum.EIM,
                False,
            ),
            (
                AuthorizationResponse(AuthorizationStatus.ONGOING, ResponseCode.OK),
                AuthEnum.EIM,
                True,
            ),
            (
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED, ResponseCode.FAILED
                ),
                AuthEnum.EIM,
                False,
            ),
        ],
    )
    async def test_eim_authorization_15118_20(
        self,
        is_authorized_response,
        auth_mode,
        next_req_is_auth_req,
    ):
        self.comm_session.evse_controller = await SimEVSEController.create()
        mock_is_authorized = AsyncMock(return_value=is_authorized_response)
        self.comm_session.evse_controller.is_authorized = mock_is_authorized

        authorization = Authorization(self.comm_session)

        await authorization.process_message(
            message=get_v2g_message_authorization_req(auth_mode)
        )
        assert authorization.expecting_authorization_req is next_req_is_auth_req

    @pytest.mark.parametrize(
        "control_mode, next_state, selected_energy_service, cp_state",
        [
            (
                ControlMode.DYNAMIC,
                ACChargeLoop,
                SelectedEnergyService(
                    service=ServiceV20.AC, is_free=True, parameter_set=None
                ),
                CpState.D2,
            ),
            (
                ControlMode.DYNAMIC,
                ACChargeLoop,
                SelectedEnergyService(
                    service=ServiceV20.AC, is_free=True, parameter_set=None
                ),
                CpState.C2,
            ),
            (
                ControlMode.DYNAMIC,
                Terminate,
                SelectedEnergyService(
                    service=ServiceV20.AC, is_free=True, parameter_set=None
                ),
                CpState.B2,
            ),
        ],
    )
    async def test_power_delivery_state_check(
        self, control_mode, next_state, selected_energy_service, cp_state
    ):
        self.comm_session.control_mode = control_mode
        self.comm_session.selected_energy_service = selected_energy_service
        power_delivery = PowerDelivery(self.comm_session)
        self.comm_session.evse_controller.get_cp_state = AsyncMock(
            return_value=cp_state
        )
        await power_delivery.process_message(
            message=get_power_delivery_req(Processing.FINISHED, ChargeProgress.START)
        )
        assert power_delivery.next_state is next_state
