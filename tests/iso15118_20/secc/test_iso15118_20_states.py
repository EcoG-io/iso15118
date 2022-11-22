from unittest.mock import Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.states.iso15118_20_states import ServiceDetail
from iso15118.shared.messages.enums import EnergyTransferModeEnum, Protocol, ServiceV20
from iso15118.shared.messages.iso15118_20.common_messages import (
    MatchedService,
    Service,
    ServiceList,
)
from iso15118.shared.messages.iso15118_20.common_types import ResponseCode
from iso15118.shared.notifications import StopNotification
from tests.dinspec.secc.test_dinspec_secc_states import MockWriter
from tests.iso15118_20.secc.test_messages import get_v2g_message_service_detail_req


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestEvScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self):
        self.comm_session = Mock(spec=SECCCommunicationSession)
        self.comm_session.session_id = "F9F9EE8505F55838"
        self.comm_session.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
        self.comm_session.selected_charging_type_is_ac = False
        self.comm_session.stop_reason = StopNotification(False, "pytest")
        self.comm_session.protocol = Protocol.ISO_15118_20_AC
        self.comm_session.writer = MockWriter()

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
