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
    get_charge_parameter_discovery_req_message_departure_time_one_hour,
    get_charge_parameter_discovery_req_message_no_departure_time,
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

    async def test_charge_parameter_discovery_res_v2g2_303(self):
        # V2G2-303 : Sum of individual time intervals shall match the period of time
        # indicated by the EVCC.
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)

        charge_parameter_discovery_req_departure_time_set = (
            get_charge_parameter_discovery_req_message_departure_time_one_hour()
        )
        charge_parameter_discovery.process_message(
            message=charge_parameter_discovery_req_departure_time_set
        )

        charging_duration = (
            charge_parameter_discovery_req_departure_time_set.body.charge_parameter_discovery_req.ac_ev_charge_parameter.departure_time  # noqa
        )

        assert (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
        )
        assert charge_parameter_discovery_res.sa_schedule_list is not None
        sa_schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )
        for schedule_tuples in sa_schedule_tuples:
            assert schedule_tuples.p_max_schedule is not None
            schedule_duration = 0
            if schedule_tuples.p_max_schedule.schedule_entries is not None:
                start_time = schedule_tuples.p_max_schedule.schedule_entries[
                    0
                ].time_interval.start

            for entry in schedule_tuples.p_max_schedule.schedule_entries:
                schedule_duration += entry.time_interval.start - start_time
                if entry.time_interval.duration is not None:
                    schedule_duration += entry.time_interval.duration
                start_time = entry.time_interval.start
            assert schedule_duration == charging_duration

    async def test_charge_parameter_discovery_res_v2g2_304(self):
        # V2G2-304: If departure time was not provided, then sum of time intervals
        # in PMaxSchedule shall be greater than or equal to 24 hours.
        twenty_four_hours_in_seconds = 86400
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        charge_parameter_discovery.process_message(
            message=get_charge_parameter_discovery_req_message_no_departure_time()
        )
        assert (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
        )
        assert charge_parameter_discovery_res.sa_schedule_list is not None
        schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )

        for schedule_tuple in schedule_tuples:
            schedule_duration = 0
            if schedule_tuple.p_max_schedule.schedule_entries is not None:
                start_time = schedule_tuple.p_max_schedule.schedule_entries[
                    0
                ].time_interval.start

            for entry in schedule_tuple.p_max_schedule.schedule_entries:
                schedule_duration += entry.time_interval.start - start_time
                if entry.time_interval.duration is not None:
                    schedule_duration += entry.time_interval.duration
                start_time = entry.time_interval.start
            assert schedule_duration >= twenty_four_hours_in_seconds

    async def test_charge_parameter_discovery_res_v2g2_761(self):
        # V2G2-761: If departure time was not provided, then SECC shall assume
        # that the EV intends to start charging without any delay
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        charge_parameter_discovery.process_message(
            message=get_charge_parameter_discovery_req_message_no_departure_time()
        )
        assert (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.next_msg.body.charge_parameter_discovery_res
        )

        assert charge_parameter_discovery_res.sa_schedule_list is not None
        sa_schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )

        for schedule_tuples in sa_schedule_tuples:
            assert schedule_tuples.p_max_schedule is not None
            found_entry_indicating_start_without_delay = False
            duration_indicating_immediate_start = 30
            for entry in schedule_tuples.p_max_schedule.schedule_entries:
                if entry.time_interval.start < duration_indicating_immediate_start:
                    found_entry_indicating_start_without_delay = True
                    break

            assert found_entry_indicating_start_without_delay is True
