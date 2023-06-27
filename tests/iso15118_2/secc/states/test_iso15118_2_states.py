from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, Mock, patch

import pytest

from iso15118.secc import Config
from iso15118.secc.controller.interface import (
    AuthorizationResponse,
    EVSessionContext15118,
)
from iso15118.secc.states.iso15118_2_states import (
    Authorization,
    ChargeParameterDiscovery,
    ChargingStatus,
    CurrentDemand,
    PaymentDetails,
    PowerDelivery,
    ServiceDetail,
    ServiceDiscovery,
    SessionSetup,
    SessionStop,
    Terminate,
    WeldingDetection,
)
from iso15118.secc.states.secc_state import StateSECC
from iso15118.shared.messages.datatypes import EVSENotification
from iso15118.shared.messages.enums import (
    AuthEnum,
    AuthorizationStatus,
    AuthorizationTokenType,
    EnergyTransferModeEnum,
    EVSEProcessing,
    Protocol,
)
from iso15118.shared.messages.iso15118_2.body import ResponseCode
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEStatus,
    AuthOptionList,
    CertificateChain,
    ChargeService,
    EnergyTransferModeList,
    ServiceCategory,
    ServiceDetails,
    ServiceID,
    ServiceName,
)
from iso15118.shared.security import get_random_bytes
from iso15118.shared.states import Pause
from tests.iso15118_2.secc.states.test_messages import (
    get_charge_parameter_discovery_req_message_departure_time_one_hour,
    get_charge_parameter_discovery_req_message_no_departure_time,
    get_dummy_charging_status_req,
    get_dummy_sa_schedule,
    get_dummy_v2g_message_authorization_req,
    get_dummy_v2g_message_payment_details_req,
    get_dummy_v2g_message_power_delivery_req_charge_start,
    get_dummy_v2g_message_power_delivery_req_charge_stop,
    get_dummy_v2g_message_service_discovery_req,
    get_dummy_v2g_message_welding_detection_req,
    get_power_delivery_req_charging_profile_in_boundary_invalid,
    get_power_delivery_req_charging_profile_in_limits,
    get_power_delivery_req_charging_profile_not_in_limits_span_over_sa,
    get_power_delivery_req_charging_profile_out_of_boundary,
    get_v2g_message_charge_parameter_discovery_req,
    get_v2g_message_power_delivery_req,
    get_v2g_message_power_delivery_req_charging_profile_in_boundary_valid,
    get_v2g_message_service_detail_req,
    get_v2g_message_service_discovery_req,
    get_v2g_message_session_setup_from_pause,
    get_v2g_message_session_stop_with_pause,
)
from tests.tools import MOCK_SESSION_ID


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestV2GSessionScenarios:
    @pytest.fixture(autouse=True)
    def _comm_session(self, comm_secc_session_mock):
        self.comm_session = comm_secc_session_mock
        self.comm_session.config = Config()
        self.comm_session.ev_session_context = EVSessionContext15118()
        self.comm_session.is_tls = False
        self.comm_session.writer = Mock()
        self.comm_session.writer.get_extra_info = Mock()

    async def test_current_demand_to_power_delivery_when_power_delivery_received(
        self,
    ):
        current_demand = CurrentDemand(self.comm_session)
        current_demand.expecting_current_demand_req = False
        await current_demand.process_message(
            message=get_v2g_message_power_delivery_req()
        )
        assert isinstance(self.comm_session.current_state, PowerDelivery)

    async def test_power_delivery_to_welding_detection_when_welding_detection_received(
        self,
    ):
        # V2G2-601 (to WeldingDetection)
        power_delivery = PowerDelivery(self.comm_session)
        power_delivery.expecting_power_delivery_req = False
        await power_delivery.process_message(
            message=get_dummy_v2g_message_welding_detection_req()
        )
        assert isinstance(self.comm_session.current_state, WeldingDetection)

    async def test_welding_detection_to_session_stop_when_session_stop_received(
        self,
    ):
        pass
        # V2G2-570

    @patch.object(
        PaymentDetails,
        "_mobility_operator_root_cert_path",
        return_value=Path(__file__).parent.parent.parent
        / "sample_certs"
        / "moRootCACert.der",
    )
    @pytest.mark.parametrize(
        "is_authorized_return_value, expected_next_state",
        [
            (
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                Authorization,
            ),
            (
                AuthorizationResponse(AuthorizationStatus.ONGOING, ResponseCode.OK),
                Authorization,
            ),
            (
                AuthorizationResponse(AuthorizationStatus.REJECTED, ResponseCode.OK),
                Terminate,
            ),
        ],
    )
    async def test_payment_details_next_state_on_payment_details_req_auth(
        self,
        mo_root_cert_path_mock,
        is_authorized_return_value: AuthorizationStatus,
        expected_next_state: StateSECC,
    ):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        mock_is_authorized = AsyncMock(return_value=is_authorized_return_value)
        self.comm_session.evse_controller.is_authorized = mock_is_authorized
        payment_details = PaymentDetails(self.comm_session)
        payment_details_req = get_dummy_v2g_message_payment_details_req()
        await payment_details.process_message(payment_details_req)

        assert isinstance(
            self.comm_session.contract_cert_chain, CertificateChain
        ), "Comm session certificate chain not populated"
        assert (
            payment_details.next_state == expected_next_state
        ), "State did not progress after PaymentDetailsReq"
        mock_is_authorized.assert_called_once()
        req_body = payment_details_req.body.payment_details_req
        assert mock_is_authorized.call_args[1]["id_token"] == req_body.emaid
        assert mock_is_authorized.call_args[1]["id_token_type"] == (
            AuthorizationTokenType.EMAID
        )

    @pytest.mark.parametrize(
        "auth_type, is_authorized_return_value, expected_next_state,"
        "expected_response_code, expected_evse_processing, is_ready_to_charge",
        [
            (
                AuthEnum.EIM,
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                ChargeParameterDiscovery,
                ResponseCode.OK,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.EIM,
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                None,
                ResponseCode.OK,
                EVSEProcessing.ONGOING,
                False,
            ),
            (
                AuthEnum.EIM,
                AuthorizationResponse(AuthorizationStatus.ONGOING, ResponseCode.OK),
                None,
                ResponseCode.OK,
                EVSEProcessing.ONGOING,
                True,
            ),
            (
                AuthEnum.EIM,
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED, ResponseCode.FAILED
                ),
                Terminate,
                ResponseCode.FAILED,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                ChargeParameterDiscovery,
                ResponseCode.OK,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(AuthorizationStatus.ACCEPTED, ResponseCode.OK),
                None,
                ResponseCode.OK,
                EVSEProcessing.ONGOING,
                False,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(AuthorizationStatus.ONGOING, ResponseCode.OK),
                None,
                ResponseCode.OK,
                EVSEProcessing.ONGOING,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED, ResponseCode.FAILED
                ),
                Terminate,
                ResponseCode.FAILED,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED,
                    ResponseCode.FAILED_CERTIFICATE_REVOKED,
                ),
                Terminate,
                ResponseCode.FAILED_CERTIFICATE_REVOKED,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED,
                    ResponseCode.FAILED_CERTIFICATE_NOT_ALLOWED_AT_THIS_EVSE,
                ),
                Terminate,
                ResponseCode.FAILED_CERTIFICATE_NOT_ALLOWED_AT_THIS_EVSE,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(
                    AuthorizationStatus.REJECTED,
                    ResponseCode.FAILED_CERTIFICATE_EXPIRED,
                ),
                Terminate,
                ResponseCode.FAILED_CERTIFICATE_EXPIRED,
                EVSEProcessing.FINISHED,
                True,
            ),
            (
                AuthEnum.PNC_V2,
                AuthorizationResponse(
                    AuthorizationStatus.ACCEPTED,
                    ResponseCode.OK_CERTIFICATE_EXPIRES_SOON,
                ),
                ChargeParameterDiscovery,
                ResponseCode.OK_CERTIFICATE_EXPIRES_SOON,
                EVSEProcessing.FINISHED,
                True,
            ),
        ],
    )
    async def test_authorization_next_state_on_authorization_request(
        self,
        auth_type: AuthEnum,
        is_authorized_return_value: AuthorizationStatus,
        expected_next_state: StateSECC,
        expected_response_code: ResponseCode,
        expected_evse_processing: EVSEProcessing,
        is_ready_to_charge: bool,
    ):
        mock_is_ready_to_charge = Mock(return_value=is_ready_to_charge)
        self.comm_session.evse_controller.ready_to_charge = mock_is_ready_to_charge
        self.comm_session.selected_auth_option = auth_type
        mock_is_authorized = AsyncMock(return_value=is_authorized_return_value)
        self.comm_session.evse_controller.is_authorized = mock_is_authorized
        # TODO: Include a real CertificateChain object and a message header
        #       with a signature that must be return by
        #      `get_dummy_v2g_message_authorization_req`
        self.comm_session.contract_cert_chain = Mock()
        self.comm_session.emaid = "dummy"
        self.comm_session.gen_challenge = None
        authorization = Authorization(self.comm_session)
        authorization.signature_verified_once = True
        await authorization.process_message(
            message=get_dummy_v2g_message_authorization_req()
        )
        assert authorization.next_state == expected_next_state
        assert (
            authorization.message.body.authorization_res.response_code
            == expected_response_code
        )
        assert (
            authorization.message.body.authorization_res.evse_processing
            == expected_evse_processing
        )

    async def test_authorization_req_gen_challenge_invalid(self):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.contract_cert_chain = Mock()
        self.comm_session.gen_challenge = get_random_bytes(16)
        id = "aReq"
        gen_challenge = get_random_bytes(16)
        authorization = Authorization(self.comm_session)

        await authorization.process_message(
            message=get_dummy_v2g_message_authorization_req(id, gen_challenge)
        )
        assert authorization.next_state == Terminate
        assert (
            authorization.message.body.authorization_res.response_code
            == ResponseCode.FAILED_CHALLENGE_INVALID
        )

    async def test_authorization_req_gen_challenge_valid(self):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.gen_challenge = get_random_bytes(16)
        id = "aReq"
        gen_challenge = self.comm_session.gen_challenge
        self.comm_session.contract_cert_chain = Mock()
        self.comm_session.emaid = "dummy"
        authorization = Authorization(self.comm_session)
        authorization.signature_verified_once = True
        await authorization.process_message(
            message=get_dummy_v2g_message_authorization_req(id, gen_challenge)
        )
        assert authorization.next_state == ChargeParameterDiscovery

    async def test_charge_parameter_discovery_res_v2g2_303(self):
        # V2G2-303 : Sum of individual time intervals shall match the period of time
        # indicated by the EVCC.
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)

        charge_parameter_discovery_req_departure_time_set = (
            get_charge_parameter_discovery_req_message_departure_time_one_hour()
        )
        await charge_parameter_discovery.process_message(
            message=charge_parameter_discovery_req_departure_time_set
        )

        charging_duration = (
            charge_parameter_discovery_req_departure_time_set.body.charge_parameter_discovery_req.ac_ev_charge_parameter.departure_time  # noqa
        )

        assert (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
        )
        assert charge_parameter_discovery_res.sa_schedule_list is not None
        sa_schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )
        for schedule_tuples in sa_schedule_tuples:
            assert schedule_tuples.p_max_schedule is not None
            schedule_duration = 0
            if schedule_tuples.p_max_schedule.schedule_entries is not None:
                first_entry_start_time = (
                    schedule_tuples.p_max_schedule.schedule_entries[
                        0
                    ].time_interval.start
                )
                last_entry_start_time = schedule_tuples.p_max_schedule.schedule_entries[
                    -1
                ].time_interval.start
                last_entry_schedule_duration = (
                    schedule_tuples.p_max_schedule.schedule_entries[
                        -1
                    ].time_interval.duration
                )
                schedule_duration = (
                    last_entry_start_time - first_entry_start_time
                ) + last_entry_schedule_duration

            assert schedule_duration == charging_duration

    async def test_charge_parameter_discovery_res_v2g2_304(self):
        # V2G2-304: If departure time was not provided, then sum of time intervals
        # in PMaxSchedule shall be greater than or equal to 24 hours.
        twenty_four_hours_in_seconds = 86400
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        await charge_parameter_discovery.process_message(
            message=get_charge_parameter_discovery_req_message_no_departure_time()
        )
        assert (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
        )
        assert charge_parameter_discovery_res.sa_schedule_list is not None
        sa_schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )

        for schedule_tuples in sa_schedule_tuples:
            schedule_duration = 0
            if schedule_tuples.p_max_schedule.schedule_entries is not None:
                first_entry_start_time = (
                    schedule_tuples.p_max_schedule.schedule_entries[
                        0
                    ].time_interval.start
                )
                last_entry_start_time = schedule_tuples.p_max_schedule.schedule_entries[
                    -1
                ].time_interval.start
                last_entry_schedule_duration = (
                    schedule_tuples.p_max_schedule.schedule_entries[
                        -1
                    ].time_interval.duration
                )
                schedule_duration = (
                    last_entry_start_time - first_entry_start_time
                ) + last_entry_schedule_duration
            assert schedule_duration >= twenty_four_hours_in_seconds

    async def test_charge_parameter_discovery_res_v2g2_761(self):
        # V2G2-761: If departure time was not provided, then SECC shall assume
        # that the EV intends to start charging without any delay
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        await charge_parameter_discovery.process_message(
            message=get_charge_parameter_discovery_req_message_no_departure_time()
        )
        assert (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
            is not None
        )
        charge_parameter_discovery_res = (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res
        )

        assert charge_parameter_discovery_res.sa_schedule_list is not None
        sa_schedule_tuples = (
            charge_parameter_discovery_res.sa_schedule_list.schedule_tuples
        )

        for schedule_tuples in sa_schedule_tuples:
            assert schedule_tuples.p_max_schedule is not None
            found_entry_indicating_start_without_delay = False
            for entry in schedule_tuples.p_max_schedule.schedule_entries:
                if entry.time_interval.start == 0:
                    found_entry_indicating_start_without_delay = True
                    break

            assert found_entry_indicating_start_without_delay is True

    @pytest.mark.parametrize(
        "power_delivery_message,expected_state, expected_response_code",
        [
            (
                get_v2g_message_power_delivery_req_charging_profile_in_boundary_valid(),
                CurrentDemand,
                ResponseCode.OK,
            ),
            (
                get_power_delivery_req_charging_profile_in_boundary_invalid(),
                Terminate,
                ResponseCode.FAILED_CHARGING_PROFILE_INVALID,
            ),
            (
                get_power_delivery_req_charging_profile_in_limits(),
                CurrentDemand,
                ResponseCode.OK,
            ),
            (
                get_power_delivery_req_charging_profile_not_in_limits_span_over_sa(),
                Terminate,
                ResponseCode.FAILED_CHARGING_PROFILE_INVALID,
            ),
            (
                get_power_delivery_req_charging_profile_out_of_boundary(),
                Terminate,
                ResponseCode.FAILED_CHARGING_PROFILE_INVALID,
            ),
        ],
    )
    async def test_charge_parameter_discovery_req_v2g2_225(
        self, power_delivery_message, expected_state, expected_response_code
    ):
        # [V2G2-225] The SECC shall send the negative ResponseCode
        # FAILED_ChargingProfileInvalid in
        # the PowerDelivery response message if the EVCC sends a ChargingProfile which
        # is not adhering to the PMax values of all PMaxScheduleEntry elements according
        # to the chosen SAScheduleTuple element in the last ChargeParameterDiscoveryRes
        # message sent by the SECC.
        self.comm_session.writer = Mock()
        self.comm_session.writer.get_extra_info = Mock()

        self.comm_session.offered_schedules = get_dummy_sa_schedule()
        power_delivery = PowerDelivery(self.comm_session)

        await power_delivery.process_message(message=power_delivery_message)
        assert power_delivery.next_state is expected_state
        assert (
            power_delivery.message.body.power_delivery_res.response_code
            is expected_response_code
        )

    async def test_power_delivery_set_hlc_charging(
        self,
    ):
        power_delivery = PowerDelivery(self.comm_session)
        self.comm_session.evse_controller.set_hlc_charging = AsyncMock()

        # hlc is set to True
        await power_delivery.process_message(
            message=get_dummy_v2g_message_power_delivery_req_charge_start()
        )

        self.comm_session.evse_controller.set_hlc_charging.assert_called_with(True)

        # hlc is set to False
        await power_delivery.process_message(
            message=get_dummy_v2g_message_power_delivery_req_charge_stop()
        )

        self.comm_session.evse_controller.set_hlc_charging.assert_called_with(False)

    async def test_service_discovery_req_unexpected_state(self):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.config.free_charging_service = False
        service_discovery = ServiceDiscovery(self.comm_session)
        await service_discovery.process_message(
            message=get_dummy_v2g_message_service_discovery_req()
        )
        await service_discovery.process_message(
            message=get_dummy_v2g_message_service_discovery_req()
        )
        assert service_discovery.next_state is Terminate
        assert (
            service_discovery.message.body.service_discovery_res.response_code
            is ResponseCode.FAILED_SEQUENCE_ERROR
        )

    async def test_charging_status_evse_status(self):
        charging_status = ChargingStatus(self.comm_session)
        self.comm_session.selected_schedule = 1
        await charging_status.process_message(message=get_dummy_charging_status_req())

        charging_status_res = charging_status.message.body.charging_status_res
        assert charging_status_res.ac_evse_status == ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
            rcd=False,
        )

    async def test_charging_status_evse_status_altered(self):
        charging_status = ChargingStatus(self.comm_session)
        self.comm_session.selected_schedule = 1

        async def get_ac_evse_status_patch():
            return ACEVSEStatus(
                notification_max_delay=0,
                evse_notification=EVSENotification.NONE,
                rcd=True,
            )

        self.comm_session.evse_controller.get_ac_evse_status = get_ac_evse_status_patch
        await charging_status.process_message(message=get_dummy_charging_status_req())
        charging_status_res = charging_status.message.body.charging_status_res
        assert charging_status_res.ac_evse_status == await get_ac_evse_status_patch()

    @pytest.mark.parametrize(
        "service_id, response_code",
        [
            (2, ResponseCode.OK),
            (3, ResponseCode.FAILED_SERVICE_ID_INVALID),
        ],
    )
    async def test_service_detail_service_id_is_in_offered_list(
        self, service_id, response_code
    ):
        self.comm_session.selected_auth_option = AuthEnum.PNC_V2
        self.comm_session.config.free_charging_service = False
        self.comm_session.writer = Mock()
        self.comm_session.writer.get_extra_info = Mock()

        cert_install_service = ServiceDetails(
            service_id=2,
            service_name=ServiceName.CERTIFICATE,
            service_category=ServiceCategory.CERTIFICATE,
            free_service=True,
        )

        self.comm_session.offered_services = []
        self.comm_session.offered_services.append(cert_install_service)
        service_details = ServiceDetail(self.comm_session)
        await service_details.process_message(
            message=get_v2g_message_service_detail_req(service_id=service_id)
        )
        assert isinstance(self.comm_session.current_state, ServiceDetail)
        assert (
            service_details.message.body.service_detail_res.response_code
            is response_code
        )

    async def test_session_pause(self):
        session_stop_state = SessionStop(self.comm_session)
        await session_stop_state.process_message(
            message=get_v2g_message_session_stop_with_pause()
        )
        assert session_stop_state.next_state is Pause

    @pytest.mark.parametrize(
        "ev_session_context, session_id, response_code",
        [
            (
                EVSessionContext15118(),
                "00",
                ResponseCode.OK_NEW_SESSION_ESTABLISHED,
            ),
            (
                EVSessionContext15118(session_id=MOCK_SESSION_ID),
                MOCK_SESSION_ID,
                ResponseCode.OK_OLD_SESSION_JOINED,
            ),
            (
                EVSessionContext15118(session_id=MOCK_SESSION_ID),
                "ABCDEF123456",
                ResponseCode.OK_NEW_SESSION_ESTABLISHED,
            ),
        ],
    )
    async def test_session_wakeup(self, ev_session_context, session_id, response_code):
        self.comm_session.ev_session_context = ev_session_context
        session_setup = SessionSetup(self.comm_session)
        await session_setup.process_message(
            message=get_v2g_message_session_setup_from_pause(session_id)
        )
        assert session_setup.response_code is response_code
        assert session_setup.next_state is ServiceDiscovery

    @pytest.mark.parametrize(
        "ev_session_context, auth_options, charge_service",
        [
            (
                EVSessionContext15118(
                    session_id=MOCK_SESSION_ID, auth_options=[AuthEnum.PNC_V2]
                ),
                [AuthEnum.PNC_V2],
                ChargeService(
                    service_id=ServiceID.CHARGING,
                    service_name=ServiceName.CHARGING,
                    service_category=ServiceCategory.CHARGING,
                    free_service=False,
                    supported_energy_transfer_mode=EnergyTransferModeList(
                        energy_modes=[
                            EnergyTransferModeEnum.DC_EXTENDED,
                            EnergyTransferModeEnum.AC_THREE_PHASE_CORE,
                        ]
                    ),
                ),
            ),
            (
                EVSessionContext15118(
                    session_id=MOCK_SESSION_ID, auth_options=[AuthEnum.EIM_V2]
                ),
                [AuthEnum.EIM_V2],
                ChargeService(
                    service_id=ServiceID.CHARGING,
                    service_name=ServiceName.CHARGING,
                    service_category=ServiceCategory.CHARGING,
                    free_service=False,
                    supported_energy_transfer_mode=EnergyTransferModeList(
                        energy_modes=[
                            EnergyTransferModeEnum.DC_EXTENDED,
                            EnergyTransferModeEnum.AC_THREE_PHASE_CORE,
                        ]
                    ),
                ),
            ),
        ],
    )
    async def test_resumed_session_auth_options_charge_service(
        self,
        ev_session_context: EVSessionContext15118,
        auth_options: List[AuthEnum],
        charge_service: ChargeService,
    ):
        self.comm_session.ev_session_context = ev_session_context
        service_discovery = ServiceDiscovery(self.comm_session)
        await service_discovery.process_message(
            message=get_v2g_message_service_discovery_req()
        )
        assert (
            service_discovery.message.body.service_discovery_res.charge_service
            == charge_service
        )

        assert (
            service_discovery.message.body.service_discovery_res.auth_option_list
            == AuthOptionList(auth_options=auth_options)
        )

    @pytest.mark.parametrize(
        "ev_session_context, schedule_tuple_id, match_status",
        [
            (
                EVSessionContext15118(
                    session_id=MOCK_SESSION_ID, sa_schedule_tuple_id=1
                ),
                1,
                True,
            ),
            (
                EVSessionContext15118(
                    session_id=MOCK_SESSION_ID, sa_schedule_tuple_id=2
                ),
                2,
                False,
            ),
        ],
    )
    async def test_resumed_session_sa_schedule_tuple(
        self,
        ev_session_context: EVSessionContext15118,
        schedule_tuple_id: int,
        match_status: bool,
    ):
        self.comm_session.ev_session_context = ev_session_context
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        energy_transfer_modes = (
            await self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.ISO_15118_2
            )
        )
        await charge_parameter_discovery.process_message(
            message=get_v2g_message_charge_parameter_discovery_req(
                energy_transfer_modes[0]
            )
        )
        sa_schedule_list = (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res.sa_schedule_list.schedule_tuples  # noqa
        )

        filtered_list = list(
            filter(
                lambda schedule_entry: schedule_entry.sa_schedule_tuple_id
                == schedule_tuple_id,
                sa_schedule_list,
            )
        )

        if match_status:
            assert len(filtered_list) == 1
        else:
            assert len(filtered_list) == 0

    @pytest.mark.parametrize(
        "free_charging_service",
        [
            False,
            True,
        ],
    )
    async def test_sales_tariff_in_free_charging_schedules(self, free_charging_service):
        self.comm_session.config.free_charging_service = free_charging_service
        charge_parameter_discovery = ChargeParameterDiscovery(self.comm_session)
        energy_transfer_modes = (
            await self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.ISO_15118_2
            )
        )
        await charge_parameter_discovery.process_message(
            message=get_v2g_message_charge_parameter_discovery_req(
                energy_transfer_modes[0]
            )
        )
        for (
            schedule_tuple
        ) in (
            charge_parameter_discovery.message.body.charge_parameter_discovery_res.sa_schedule_list.schedule_tuples  # noqa
        ):
            assert (
                schedule_tuple.sales_tariff is None
                if free_charging_service
                else not None
            )
