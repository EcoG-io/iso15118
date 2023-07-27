import time

from iso15118.shared.messages.enums import AuthEnum, ControlMode, ServiceV20
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    ChargeProgress,
    ContractCertificateChain,
    DynamicEVPowerProfile,
    DynamicScheduleExchangeReqParams,
    EIMAuthReqParams,
    EVPowerProfile,
    EVPowerProfileEntryList,
    PnCAuthReqParams,
    PowerDeliveryReq,
    PowerScheduleEntry,
    ScheduledScheduleExchangeReqParams,
    ScheduleExchangeReq,
    ServiceDetailReq,
    SubCertificates,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    RationalNumber,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryReqParams,
    DCCableCheckReq,
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryReqParams,
    DCPreChargeReq,
)
from iso15118.shared.security import get_random_bytes
from tests.tools import MOCK_SESSION_ID


def get_v2g_message_service_detail_req(service_list: int) -> ServiceDetailReq:
    return ServiceDetailReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        service_id=service_list,
    )


def get_v2g_message_authorization_req(auth_service: AuthEnum) -> AuthorizationReq:
    eim_params = None
    pnc_params = None
    if auth_service == AuthEnum.EIM:
        eim_params = EIMAuthReqParams()
    else:
        pnc_params = PnCAuthReqParams(
            gen_challenge=get_random_bytes(16),
            contract_cert_chain=ContractCertificateChain(
                certificate=b"00", sub_certificates=SubCertificates(certificates=[])
            ),
        )
    return AuthorizationReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        selected_auth_service=auth_service,
        eim_params=eim_params,
        pnc_params=pnc_params,
    )


def get_v2g_message_dc_charge_parameter_discovery_req(
    service: ServiceV20,
) -> DCChargeParameterDiscoveryReq:
    dc_params = DCChargeParameterDiscoveryReqParams(
        ev_max_charge_power=RationalNumber(exponent=3, value=300),
        ev_min_charge_power=RationalNumber(exponent=0, value=100),
        ev_max_charge_current=RationalNumber(exponent=0, value=300),
        ev_min_charge_current=RationalNumber(exponent=0, value=10),
        ev_max_voltage=RationalNumber(exponent=0, value=1000),
        ev_min_voltage=RationalNumber(exponent=0, value=10),
    )
    bpt_dc_params = None
    if service == ServiceV20.DC_BPT:
        bpt_dc_params = BPTDCChargeParameterDiscoveryReqParams(
            **(dc_params.dict()),
            ev_max_discharge_power=RationalNumber(exponent=3, value=11),
            ev_min_discharge_power=RationalNumber(exponent=3, value=1),
            ev_max_discharge_current=RationalNumber(exponent=0, value=11),
            ev_min_discharge_current=RationalNumber(exponent=0, value=0),
        )
        dc_params = None

    return DCChargeParameterDiscoveryReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        dc_params=dc_params,
        bpt_dc_params=bpt_dc_params,
    )


def get_schedule_exchange_req_message(control_mode: ControlMode):
    scheduled_params, dynamic_params = None, None
    if control_mode == ControlMode.SCHEDULED:
        scheduled_params = ScheduledScheduleExchangeReqParams(
            departure_time=7200,
            ev_target_energy_request=RationalNumber(exponent=3, value=10),
            ev_max_energy_request=RationalNumber(exponent=3, value=20),
            ev_min_energy_request=RationalNumber(exponent=-2, value=5),
        )

    if control_mode == ControlMode.DYNAMIC:
        dynamic_params = DynamicScheduleExchangeReqParams(
            departure_time=7200,
            min_soc=30,
            target_soc=80,
            ev_target_energy_request=RationalNumber(exponent=3, value=40),
            ev_max_energy_request=RationalNumber(exponent=1, value=6000),
            ev_min_energy_request=RationalNumber(exponent=0, value=-20000),
            ev_max_v2x_energy_request=RationalNumber(exponent=0, value=5000),
            ev_min_v2x_energy_request=RationalNumber(exponent=0, value=0),
        )

    return ScheduleExchangeReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        max_supporting_points=12,
        scheduled_params=scheduled_params,
        dynamic_params=dynamic_params,
    )


def get_cable_check_req():
    return DCCableCheckReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        )
    )


def get_precharge_req(processing: Processing):
    return DCPreChargeReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        ev_processing=processing,
        ev_present_voltage=RationalNumber(exponent=0, value=10),
        ev_target_voltage=RationalNumber(exponent=0, value=10),
    )


def get_power_delivery_req(processing: Processing, charge_progress: ChargeProgress):
    return PowerDeliveryReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        ev_processing=processing,
        charge_progress=charge_progress,
        ev_power_profile=EVPowerProfile(
            time_anchor=0,
            entry_list=EVPowerProfileEntryList(
                entries=[
                    PowerScheduleEntry(
                        duration=10, power=RationalNumber(exponent=0, value=10)
                    )
                ]
            ),
            dynamic_profile=DynamicEVPowerProfile(),
        ),
    )
