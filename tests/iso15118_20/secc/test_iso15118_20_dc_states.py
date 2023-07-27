from typing import Type
from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.secc.comm_session_handler import SECCCommunicationSession
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.failed_responses import init_failed_responses_iso_v20
from iso15118.secc.states.iso15118_20_states import (
    DCCableCheck,
    DCChargeLoop,
    DCChargeParameterDiscovery,
    DCPreCharge,
    PowerDelivery,
    ScheduleExchange,
)
from iso15118.shared.messages.enums import (
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Protocol,
    ServiceV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ChargeProgress,
    SelectedEnergyService,
)
from iso15118.shared.messages.iso15118_20.common_types import Processing
from iso15118.shared.notifications import StopNotification
from iso15118.shared.states import State, Terminate
from tests.dinspec.secc.test_dinspec_secc_states import MockWriter
from tests.iso15118_20.secc.test_messages import (
    get_cable_check_req,
    get_power_delivery_req,
    get_precharge_req,
    get_schedule_exchange_req_message,
    get_v2g_message_dc_charge_parameter_discovery_req,
)


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
        self.comm_session.protocol = Protocol.ISO_15118_20_DC
        self.comm_session.writer = MockWriter()
        self.comm_session.failed_responses_isov20 = init_failed_responses_iso_v20()
        self.comm_session.evse_controller = SimEVSEController()

    @pytest.mark.parametrize(
        "service_type, dc_params, bpt_params",
        [
            (ServiceV20.DC, "", None),
            (ServiceV20.DC_BPT, None, ""),
        ],
    )
    async def test_15118_20_dc_charge_parameter_discovery_res(
        self, service_type, dc_params, bpt_params
    ):
        self.comm_session.selected_energy_service = SelectedEnergyService(
            service=service_type,
            is_free=True,
            parameter_set=None,
        )
        dc_charge_parameter_discovery = DCChargeParameterDiscovery(self.comm_session)
        await dc_charge_parameter_discovery.process_message(
            message=get_v2g_message_dc_charge_parameter_discovery_req(service_type)
        )
        if service_type == ServiceV20.DC:
            assert bpt_params is None
        elif service_type == ServiceV20.DC_BPT:
            assert dc_params is None
        assert dc_charge_parameter_discovery.next_state is ScheduleExchange

    @pytest.mark.parametrize(
        "control_mode, next_state, selected_energy_service",
        [
            (
                ControlMode.SCHEDULED,
                None,
                SelectedEnergyService(
                    service=ServiceV20.DC, is_free=True, parameter_set=None
                ),
            ),
            (
                ControlMode.DYNAMIC,
                None,
                SelectedEnergyService(
                    service=ServiceV20.DC, is_free=True, parameter_set=None
                ),
            ),
            (
                ControlMode.SCHEDULED,
                None,
                SelectedEnergyService(
                    service=ServiceV20.DC_BPT, is_free=True, parameter_set=None
                ),
            ),
            (
                ControlMode.DYNAMIC,
                None,
                SelectedEnergyService(
                    service=ServiceV20.DC_BPT, is_free=True, parameter_set=None
                ),
            ),
        ],
    )
    async def test_15118_20_schedule_exchange_res(
        self,
        control_mode: ControlMode,
        next_state: Type[State],
        selected_energy_service: SelectedEnergyService,
    ):
        self.comm_session.control_mode = control_mode
        self.comm_session.selected_energy_service = selected_energy_service
        schedule_exchange = ScheduleExchange(self.comm_session)
        await schedule_exchange.process_message(
            message=get_schedule_exchange_req_message(control_mode)
        )
        assert schedule_exchange.next_state is None

    @pytest.mark.parametrize(
        "cable_check_req_received, "
        "is_contactor_closed, "
        "cable_check_status, "
        "expected_state",
        [
            (False, False, None, Terminate),
            (False, True, None, None),
            (False, True, IsolationLevel.VALID, DCPreCharge),
            (True, True, None, None),
            (True, True, IsolationLevel.VALID, DCPreCharge),
        ],
    )
    async def test_15118_20_dc_cable_check(
        self,
        cable_check_req_received: bool,
        is_contactor_closed: bool,
        cable_check_status: IsolationLevel,
        expected_state: Type[State],
    ):
        dc_cable_check = DCCableCheck(self.comm_session)
        dc_cable_check.cable_check_req_was_received = cable_check_req_received
        contactor_status = AsyncMock(return_value=is_contactor_closed)
        self.comm_session.evse_controller.is_contactor_closed = contactor_status
        cable_check_status = AsyncMock(return_value=cable_check_status)
        self.comm_session.evse_controller.get_cable_check_status = cable_check_status
        await dc_cable_check.process_message(message=get_cable_check_req())
        assert dc_cable_check.next_state is expected_state

    @pytest.mark.parametrize(
        "processing, expected_state",
        [(Processing.ONGOING, None), (Processing.FINISHED, PowerDelivery)],
    )
    async def test_15118_20_precharge(
        self, processing: Processing, expected_state: Type[State]
    ):
        dc_pre_charge = DCPreCharge(self.comm_session)
        await dc_pre_charge.process_message(message=get_precharge_req(processing))
        assert dc_pre_charge.next_state is expected_state

    async def test_15118_20_power_delivery(self):
        # TODO
        pass

    @pytest.mark.parametrize(
        "control_mode, next_state, selected_energy_service, cp_state",
        [
            (
                ControlMode.DYNAMIC,
                DCChargeLoop,
                SelectedEnergyService(
                    service=ServiceV20.DC, is_free=True, parameter_set=None
                ),
                CpState.D2,
            ),
            (
                ControlMode.DYNAMIC,
                DCChargeLoop,
                SelectedEnergyService(
                    service=ServiceV20.DC, is_free=True, parameter_set=None
                ),
                CpState.C2,
            ),
            (
                ControlMode.DYNAMIC,
                Terminate,
                SelectedEnergyService(
                    service=ServiceV20.DC, is_free=True, parameter_set=None
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
