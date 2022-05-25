from typing import List

from iso15118.shared.messages.enums import UnitSymbol
from iso15118.shared.messages.iso15118_2.body import (
    AuthorizationReq,
    Body,
    PowerDeliveryReq,
    SessionStopReq,
    WeldingDetectionReq,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
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
        header=MessageHeader(session_id="F9F9EE8505F55838"),
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
        header=MessageHeader(session_id="F9F9EE8505F55838"),
        body=Body(welding_detection_req=welding_detection_req),
    )


def get_dummy_v2g_message_session_stop_req():
    session_stop_req = SessionStopReq(
        charging_session=ChargingSession.TERMINATE,
    )

    return V2GMessage(
        header=MessageHeader(session_id="F9F9EE8505F55838"),
        body=Body(session_stop_req=session_stop_req),
    )


def get_dummy_v2g_message_authorization_req():
    # The AuthorizationReq is empty, unless it is following a PaymentDetailsRes
    # message, in which case it must send back the generated challenge.
    authorization_req = AuthorizationReq()

    # TODO: replace this with a constant
    return V2GMessage(
        header=MessageHeader(session_id="F9F9EE8505F55838"),
        body=Body(authorization_req=authorization_req),
    )
