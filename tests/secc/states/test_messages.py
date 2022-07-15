from typing import List

from iso15118.shared.messages.datatypes import (
    PVEAmount,
    PVEVMaxCurrent,
    PVEVMaxVoltage,
    PVEVMinCurrent,
)
from iso15118.shared.messages.enums import EnergyTransferModeEnum, UnitSymbol
from iso15118.shared.messages.iso15118_2.body import (
    AuthorizationReq,
    Body,
    ChargeParameterDiscoveryReq,
    PaymentDetailsReq,
    PowerDeliveryReq,
    SessionStopReq,
    WeldingDetectionReq,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVChargeParameter,
    CertificateChain,
    ChargeProgress,
    ChargingSession,
    DCEVErrorCode,
    DCEVStatus,
    PMaxSchedule,
    PMaxScheduleEntry,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
)
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
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


def get_dummy_v2g_message_authorization_req():
    # The AuthorizationReq is empty, unless it is following a PaymentDetailsRes
    # message, in which case it must send back the generated challenge.
    authorization_req = AuthorizationReq()

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(authorization_req=authorization_req),
    )


def get_dummy_v2g_message_payment_details_req() -> V2GMessage:
    with open("sample_certs/cpsLeafCert.pem", "rb") as leaf_file:
        leaf_certificate = leaf_file.read()
    with open("sample_certs/cpsSubCA1Cert.pem", "rb") as sub_ca_1_file:
        sub_ca_1_certificate = sub_ca_1_file.read()
    with open("sample_certs/cpsSubCA2Cert.pem", "rb") as sub_ca_2_file:
        sub_ca_2_certificate = sub_ca_2_file.read()

    payment_details_req = PaymentDetailsReq(
        emaid="1234567890abcd",
        cert_chain=CertificateChain(
            certificate=leaf_certificate,
            sub_certificates=[sub_ca_2_certificate, sub_ca_1_certificate]
        ),
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


def get_dummy_v2g_message_power_delivery_req_charge_stop():
    power_delivery_req = PowerDeliveryReq(
        charge_progress=ChargeProgress.STOP,
        sa_schedule_tuple_id=1,
    )

    return V2GMessage(
        header=MessageHeader(session_id=MOCK_SESSION_ID),
        body=Body(power_delivery_req=power_delivery_req),
    )
