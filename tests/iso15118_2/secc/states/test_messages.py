from typing import List, Optional

from iso15118.shared.messages.datatypes import (
    PVEAmount,
    PVEVMaxCurrent,
    PVEVMaxCurrentLimit,
    PVEVMaxVoltage,
    PVEVMaxVoltageLimit,
    PVEVMinCurrent,
)
from iso15118.shared.messages.enums import EnergyTransferModeEnum, UnitSymbol
from iso15118.shared.messages.iso15118_2.body import (
    AuthorizationReq,
    Body,
    CableCheckReq,
    ChargeParameterDiscoveryReq,
    ChargingStatusReq,
    PaymentDetailsReq,
    PowerDeliveryReq,
    ServiceDetailReq,
    ServiceDiscoveryReq,
    SessionSetupReq,
    SessionStopReq,
    WeldingDetectionReq,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVChargeParameter,
    ChargeProgress,
    ChargingProfile,
    ChargingSession,
    DCEVChargeParameter,
    DCEVErrorCode,
    DCEVStatus,
    PMaxSchedule,
    PMaxScheduleEntry,
    ProfileEntryDetails,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
)
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from tests.iso15118_2.sample_certs.load_certs import load_certificate_chain
from tests.tools import MOCK_SESSION_ID


def get_sa_schedule_list():
    """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
    sa_schedule_list: List[SAScheduleTuple] = []

    # PMaxSchedule
    p_max = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
    entry_details = PMaxScheduleEntry(
        p_max=p_max, time_interval=RelativeTimeInterval(start=0, duration=3600)
    )
    p_max_schedule_entries = [entry_details]
    p_max_schedule_entry = PMaxSchedule(schedule_entries=p_max_schedule_entries)

    # SalesTariff
    sales_tariff_entries: List[SalesTariffEntry] = []
    sales_tariff_entry_1 = SalesTariffEntry(
        e_price_level=1, time_interval=RelativeTimeInterval(start=0)
    )

    sales_tariff_entries.append(sales_tariff_entry_1)
    sales_tariff = SalesTariff(
        id="id1",
        sales_tariff_id=10,  # a random id
        sales_tariff_entry=sales_tariff_entries,
        num_e_price_levels=1,
    )

    # Putting the list of SAScheduleTuple entries together
    sa_schedule_tuple_entry = SAScheduleTuple(
        sa_schedule_tuple_id=1,
        p_max_schedule=p_max_schedule_entry,
        sales_tariff=sales_tariff,
    )

    sa_schedule_list.append(sa_schedule_tuple_entry)

    return sa_schedule_list


def get_v2g_message_power_delivery_req():
    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.STOP,
        sa_schedule_tuple_id=1,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_dummy_dc_ev_status():
    return DCEVStatus(
        ev_ready=True,
        ev_error_code=DCEVErrorCode.NO_ERROR,
        ev_ress_soc=77,
    )


def get_dummy_v2g_message_welding_detection_req():
    welding_detection_req = WeldingDetectionReq(
        dc_ev_status=get_dummy_dc_ev_status(),
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(welding_detection_req=welding_detection_req),
    )


def get_dummy_v2g_message_session_stop_req():
    session_stop_req = SessionStopReq(
        charging_session=ChargingSession.TERMINATE,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(session_stop_req=session_stop_req),
    )


def get_dummy_v2g_message_authorization_req(
    id: Optional[str] = None, gen_challenge: Optional[bytes] = None
):
    # The AuthorizationReq is empty, unless it is following a PaymentDetailsRes
    # message, in which case it must send back the generated challenge.
    if gen_challenge:
        authorization_req = AuthorizationReq(id=id, gen_challenge=gen_challenge)
    else:
        authorization_req = AuthorizationReq()
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(authorization_req=authorization_req),
    )


def get_dummy_v2g_message_payment_details_req(
    contract: Optional[str] = None,
) -> V2GMessage:
    payment_details_req = PaymentDetailsReq(
        emaid="1234567890abcd",
        cert_chain=load_certificate_chain(contract),
    )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(payment_details_req=payment_details_req),
    )


def get_charge_parameter_discovery_req_message_departure_time_one_hour():
    e_amount = PVEAmount(multiplier=0, value=60, unit=UnitSymbol.WATT_HOURS)
    ev_max_voltage = PVEVMaxVoltage(multiplier=0, value=400, unit=UnitSymbol.VOLTAGE)
    ev_max_current = PVEVMaxCurrent(multiplier=-3, value=32000, unit=UnitSymbol.AMPERE)
    ev_min_current = PVEVMinCurrent(multiplier=0, value=10, unit=UnitSymbol.AMPERE)
    one_hour_in_seconds = 3600
    ac_charge_params = ACEVChargeParameter(
        departure_time=one_hour_in_seconds,
        e_amount=e_amount,
        ev_max_voltage=ev_max_voltage,
        ev_max_current=ev_max_current,
        ev_min_current=ev_min_current,
    )

    charge_parameter_discovery_req = ChargeParameterDiscoveryReq(
        requested_energy_mode=EnergyTransferModeEnum.AC_THREE_PHASE_CORE,
        ac_ev_charge_parameter=ac_charge_params,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(charge_parameter_discovery_req=charge_parameter_discovery_req),
    )


def get_charge_parameter_discovery_req_message_no_departure_time():
    e_amount = PVEAmount(multiplier=0, value=60, unit=UnitSymbol.WATT_HOURS)
    ev_max_voltage = PVEVMaxVoltage(multiplier=0, value=400, unit=UnitSymbol.VOLTAGE)
    ev_max_current = PVEVMaxCurrent(multiplier=-3, value=32000, unit=UnitSymbol.AMPERE)
    ev_min_current = PVEVMinCurrent(multiplier=0, value=10, unit=UnitSymbol.AMPERE)
    ac_charge_params = ACEVChargeParameter(
        e_amount=e_amount,
        ev_max_voltage=ev_max_voltage,
        ev_max_current=ev_max_current,
        ev_min_current=ev_min_current,
    )

    charge_parameter_discovery_req = ChargeParameterDiscoveryReq(
        requested_energy_mode=EnergyTransferModeEnum.AC_THREE_PHASE_CORE,
        ac_ev_charge_parameter=ac_charge_params,
        dc_ev_charge_parameter=None,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(charge_parameter_discovery_req=charge_parameter_discovery_req),
    )


def get_dummy_v2g_message_power_delivery_req_charge_start():
    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_v2g_message_power_delivery_req_invalid_charging_profile():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=12000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1800,
                max_power=PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_v2g_message_power_delivery_req_charging_profile_in_boundary_valid():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1800,
                max_power=PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_power_delivery_req_charging_profile_in_boundary_invalid():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=10000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1800,
                max_power=PVPMax(multiplier=0, value=8000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_power_delivery_req_charging_profile_in_limits():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=10000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1200,
                max_power=PVPMax(multiplier=0, value=8000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1800,
                max_power=PVPMax(multiplier=0, value=6000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_power_delivery_req_charging_profile_not_in_limits():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=10000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2000,
                max_power=PVPMax(multiplier=0, value=8000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_power_delivery_req_charging_profile_not_in_limits_span_over_sa():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1200,
                max_power=PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1900,
                max_power=PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_dummy_sa_schedule():
    sa_schedule_list: list[SAScheduleTuple] = []
    # PMaxSchedule
    p_max_schedule_entry_1 = PMaxScheduleEntry(
        p_max=PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT),
        time_interval=RelativeTimeInterval(start=0, duration=1800),
    )
    p_max_schedule_entry_2 = PMaxScheduleEntry(
        p_max=PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT),
        time_interval=RelativeTimeInterval(start=1800, duration=1800),
    )

    p_max_schedule = PMaxSchedule(
        schedule_entries=[p_max_schedule_entry_1, p_max_schedule_entry_2]
    )
    # Putting the list of SAScheduleTuple entries together
    sa_schedule_tuple = SAScheduleTuple(
        sa_schedule_tuple_id=1,
        p_max_schedule=p_max_schedule,
    )
    sa_schedule_list.append(sa_schedule_tuple)
    return sa_schedule_list


def get_power_delivery_req_charging_profile_out_of_boundary():
    charging_profile = ChargingProfile(
        profile_entries=[
            ProfileEntryDetails(
                start=0,
                max_power=PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1000,
                max_power=PVPMax(multiplier=0, value=10000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=1800,
                max_power=PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2000,
                max_power=PVPMax(multiplier=0, value=5000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2100,
                max_power=PVPMax(multiplier=0, value=6300, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2300,
                max_power=PVPMax(multiplier=0, value=2000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2400,
                max_power=PVPMax(multiplier=0, value=4000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2450,
                max_power=PVPMax(multiplier=0, value=700, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=2500,
                max_power=PVPMax(multiplier=0, value=6999, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=3000,
                max_power=PVPMax(multiplier=0, value=1400, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
            ProfileEntryDetails(
                start=3100,
                max_power=PVPMax(multiplier=0, value=8000, unit=UnitSymbol.WATT),
                max_phases_in_use=3,
            ),
        ]
    )

    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.START,
        sa_schedule_tuple_id=1,
        charging_profile=charging_profile,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_dummy_v2g_message_power_delivery_req_charge_stop():
    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.STOP,
        sa_schedule_tuple_id=1,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )


def get_dummy_v2g_message_service_discovery_req() -> V2GMessage:
    service_discovery_req = ServiceDiscoveryReq()
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_discovery_req=service_discovery_req),
    )


def get_dummy_charging_status_req() -> V2GMessage:
    charging_status_req = ChargingStatusReq()
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(charging_status_req=charging_status_req),
    )


def get_v2g_message_service_detail_req(service_id) -> V2GMessage:
    service_detail_req = ServiceDetailReq(service_id=service_id)
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_detail_req=service_detail_req),
    )


def get_v2g_message_session_stop_with_pause() -> V2GMessage:
    session_stop_pause_req = SessionStopReq(charging_session=ChargingSession.PAUSE)
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(session_stop_req=session_stop_pause_req),
    )


def get_v2g_message_session_setup_from_pause(session_id: str) -> V2GMessage:
    session_setup_req = SessionSetupReq(evcc_id="ABCDEF123456")
    return V2GMessage(
        header=MessageHeader(session_id=session_id),
        body=Body(session_setup_req=session_setup_req),
    )


def get_v2g_message_service_discovery_req() -> V2GMessage:
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(service_discovery_req=ServiceDiscoveryReq()),
    )


def get_v2g_message_charge_parameter_discovery_req(
    energy_transfer_mode: EnergyTransferModeEnum,
) -> V2GMessage:
    ac_cp = None
    dc_cp = None
    if energy_transfer_mode.startswith("AC"):
        ac_cp = ACEVChargeParameter(
            e_amount=PVEAmount(value=1, multiplier=1, unit=UnitSymbol.WATT_HOURS),
            ev_max_voltage=PVEVMaxVoltage(
                value=1, multiplier=1, unit=UnitSymbol.VOLTAGE
            ),
            ev_max_current=PVEVMaxCurrent(
                value=2, multiplier=1, unit=UnitSymbol.AMPERE
            ),
            ev_min_current=PVEVMinCurrent(
                value=1, multiplier=1, unit=UnitSymbol.AMPERE
            ),
        )
    else:
        dc_cp = DCEVChargeParameter(
            dc_ev_status=DCEVStatus(
                ev_ready=True,
                ev_error_code=DCEVErrorCode.NO_ERROR,
                ev_ress_soc=50,
            ),
            ev_maximum_current_limit=PVEVMaxCurrentLimit(
                value=1, multiplier=1, unit=UnitSymbol.AMPERE
            ),
            ev_maximum_voltage_limit=PVEVMaxVoltageLimit(
                value=1, multiplier=1, unit=UnitSymbol.VOLTAGE
            ),
        )
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=energy_transfer_mode,
                ac_ev_charge_parameter=ac_cp,
                dc_ev_charge_parameter=dc_cp,
            )
        ),
    )


def get_cable_check_req() -> V2GMessage:
    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(
            cable_check_req=CableCheckReq(
                dc_ev_status=DCEVStatus(
                    ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=35
                )
            )
        ),
    )
