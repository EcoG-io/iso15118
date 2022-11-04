import os
from unittest.mock import Mock

import pytest
import pytest_asyncio

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.secc import Config
from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.evse_config import build_evse_configs
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.failed_responses import init_failed_responses_iso_v2
from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.datatypes import EnergyTransferModeEnum
from iso15118.shared.notifications import StopNotification
from tests.configs.evse_configs.iso15118_2.dc.sample_cs_configs import get_cs_config_dc
from tests.configs.evse_configs.iso15118_2.dc.sample_cs_limits import get_cs_limits_dc
from tests.secc.states.test_messages import get_sa_schedule_list
from tests.tools import MOCK_SESSION_ID


async def build_evse_controller():
    cs_config = get_cs_config_dc()
    cs_limits = get_cs_limits_dc()
    evse_configs = await build_evse_configs(cs_config=cs_config, cs_limits=cs_limits)
    evse_controllers = {}
    for key, value in evse_configs.items():
        sim_evse_controller = await SimEVSEController.create(evse_config=value)
        evse_controllers[key] = sim_evse_controller
    first_evse_controller = list(evse_controllers.values())[0]
    return first_evse_controller


@pytest.fixture
def comm_evcc_session_mock():
    comm_session_mock = Mock(spec=EVCCCommunicationSession)
    comm_session_mock.session_id = MOCK_SESSION_ID
    comm_session_mock.stop_reason = StopNotification(False, "pytest")
    comm_session_mock.ev_controller = SimEVController()
    comm_session_mock.protocol = Protocol.UNKNOWN
    comm_session_mock.selected_schedule = 1
    comm_session_mock.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
    comm_session_mock.selected_charging_type_is_ac = False
    return comm_session_mock


@pytest_asyncio.fixture
async def comm_secc_session_mock():
    comm_session_mock = Mock(spec=SECCCommunicationSession)
    comm_session_mock.failed_responses_isov2 = init_failed_responses_iso_v2()
    comm_session_mock.session_id = MOCK_SESSION_ID
    comm_session_mock.offered_schedules = get_sa_schedule_list()
    comm_session_mock.selected_energy_mode = EnergyTransferModeEnum.DC_EXTENDED
    comm_session_mock.selected_charging_type_is_ac = False
    comm_session_mock.stop_reason = StopNotification(False, "pytest")
    comm_session_mock.evse_controller = await build_evse_controller()
    comm_session_mock.protocol = Protocol.UNKNOWN
    return comm_session_mock
