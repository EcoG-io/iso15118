import time
from typing import List
from unittest.mock import Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.states.iso15118_20_states import ServiceDiscovery
from iso15118.shared.messages.enums import EnergyTransferModeEnum, Protocol, ServiceV20
from iso15118.shared.messages.iso15118_20.common_messages import (
    MatchedService,
    ServiceDiscoveryReq,
    ServiceIDList,
)
from iso15118.shared.messages.iso15118_20.common_types import MessageHeader
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
        self.comm_session.protocol = Protocol.ISO_15118_20_AC
        self.comm_session.writer = MockWriter()
        self.comm_session.matched_services_v20: List[MatchedService] = []

    def service_discovery_req(self, service_ids):
        service_list: ServiceIDList = ServiceIDList(service_ids=service_ids)

        return ServiceDiscoveryReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            ),
            supported_service_ids=service_list,
        )

    async def test_energy_list(self):
        service_ids = [
            ServiceV20.AC.value,
            ServiceV20.AC_BPT.value,
            ServiceV20.DC_ACDP_BPT.value,
        ]
        service_discovery: ServiceDiscovery = ServiceDiscovery(self.comm_session)
        service_discovery_req = self.service_discovery_req(service_ids)
        await service_discovery.process_message(message=service_discovery_req)
        assert len(self.comm_session.matched_services_v20) == 2
        assert self.comm_session.matched_services_v20[0].service == ServiceV20.AC
        assert self.comm_session.matched_services_v20[1].service == ServiceV20.AC_BPT
        assert service_discovery.next_state is None

        self.comm_session.matched_services_v20.clear()
        service_ids = [ServiceV20.DC.value, ServiceV20.DC_BPT.value]
        service_discovery: ServiceDiscovery = ServiceDiscovery(self.comm_session)
        service_discovery_req = self.service_discovery_req(service_ids)
        await service_discovery.process_message(message=service_discovery_req)
        print(self.comm_session.matched_services_v20)
        assert len(self.comm_session.matched_services_v20) == 0
        assert service_discovery.next_state is None
