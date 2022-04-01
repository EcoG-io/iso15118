"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import logging
import time
from typing import List, Optional, Union

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.exceptions import InvalidProtocolError
from iso15118.shared.messages.datatypes_iso15118_2_dinspec import (
    PVEVSEPresentVoltage,
    PVEVSEPresentCurrent,
    EVSENotification,
    DCEVSEStatusCode,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVTargetVoltage,
    PVEVTargetCurrent,
)
from iso15118.shared.messages.enums import (
    Namespace,
    Protocol,
    EnergyTransferModeEnum,
    UnitSymbol,
    EVSEProcessing,
    IsolationLevel,
)
from iso15118.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
    PMaxScheduleEntry as PMaxScheduleEntryDINSPEC,
    RelativeTimeInterval as RelativeTimeIntervalDINSPEC,
    PMaxScheduleEntryDetails as PMaxScheduleEntryDetailsDINSPEC,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PMaxScheduleEntry,
    PMaxScheduleEntryDetails,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTupleEntry,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20

logger = logging.getLogger(__name__)


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    def get_evse_id(self, protocol: Protocol) -> str:
        if protocol == Protocol.DIN_SPEC_70121:
            #  To transform a string-based DIN SPEC 91286 EVSE ID to hexBinary
            #  representation and vice versa, the following conversion rules shall
            #  be used for each character and hex digit: '0' <--> 0x0, '1' <--> 0x1,
            #  '2' <--> 0x2, '3' <--> 0x3, '4' <--> 0x4, '5' <--> 0x5, '6' <--> 0x6,
            #  '7' <--> 0x7, '8' <--> 0x8, '9' <--> 0x9, '*' <--> 0xA,
            #  Unused <--> 0xB .. 0xF.
            # Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
            # as “0x49 0xA8 0x9A 0x63 0x60”.
            return "49A89A6360"
        """Overrides EVSEControllerInterface.get_evse_id()."""
        return "UK123E1234"

    def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""
        if protocol == Protocol.DIN_SPEC_70121:
            dc_core = EnergyTransferModeEnum.DC_CORE
            dc_extended = EnergyTransferModeEnum.DC_EXTENDED
            return [dc_extended, dc_core]

        ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        return [ac_single_phase, ac_three_phase]

    def is_authorised(self) -> bool:
        """Overrides EVSEControllerInterface.is_authorised()."""
        return True

    def get_sa_schedule_list_dinspec(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntryDINSPEC]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list_dinspec()."""
        sa_schedule_list: List[SAScheduleTupleEntryDINSPEC] = []
        entry_details = PMaxScheduleEntryDetailsDINSPEC(
            p_max=200, time_interval=RelativeTimeIntervalDINSPEC(start=0, duration=3600)
        )
        p_max_schedule_entries = [entry_details]
        pmax_schedule_entry = PMaxScheduleEntryDINSPEC(
            p_max_schedule_id=0, entry_details=p_max_schedule_entries
        )

        sa_schedule_tuple_entry = SAScheduleTupleEntryDINSPEC(
            sa_schedule_tuple_id=1,
            p_max_schedule=pmax_schedule_entry,
            sales_tariff=None,
        )
        sa_schedule_list.append(sa_schedule_tuple_entry)
        return sa_schedule_list

    def get_sa_schedule_list(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntry]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTupleEntry] = []

        # PMaxSchedule
        p_max = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
        entry_details = PMaxScheduleEntryDetails(
            p_max=p_max, time_interval=RelativeTimeInterval(start=0, duration=3600)
        )
        p_max_schedule_entries = [entry_details]
        p_max_schedule_entry = PMaxScheduleEntry(entry_details=p_max_schedule_entries)

        # SalesTariff
        sales_tariff_entries: List[SalesTariffEntry] = []
        sales_tariff_entry_1 = SalesTariffEntry(
            e_price_level=1, time_interval=RelativeTimeInterval(start=0)
        )
        sales_tariff_entry_2 = SalesTariffEntry(
            e_price_level=2,
            time_interval=RelativeTimeInterval(start=1801, duration=1799),
        )
        sales_tariff_entries.append(sales_tariff_entry_1)
        sales_tariff_entries.append(sales_tariff_entry_2)
        sales_tariff = SalesTariff(
            id="id1",
            sales_tariff_id=10,  # a random id
            sales_tariff_entry=sales_tariff_entries,
            num_e_price_levels=2,
        )

        # Putting the list of SAScheduleTuple entries together
        sa_schedule_tuple_entry = SAScheduleTupleEntry(
            sa_schedule_tuple_id=1,
            p_max_schedule=p_max_schedule_entry,
            sales_tariff=sales_tariff,
        )

        # TODO We could also implement an optional SalesTariff, but for the sake of
        #      time we'll do that later (after the basics are implemented).
        #      When implementing the SalesTariff, we also need to apply a digital
        #      signature to it.
        sa_schedule_list.append(sa_schedule_tuple_entry)

        # TODO We need to take care of [V2G2-741], which says that the SECC needs to
        #      resend a previously agreed SAScheduleTuple and the "period of time
        #      this SAScheduleTuple applies for shall be reduced by the time already
        #      elapsed".

        return sa_schedule_list

    def get_meter_info(self, protocol: Protocol) -> Union[MeterInfoV2, MeterInfoV20]:
        """Overrides EVSEControllerInterface.get_meter_info()."""
        if protocol == Protocol.ISO_15118_2:
            return MeterInfoV2(
                meter_id="Switch-Meter-123", meter_reading=12345, t_meter=time.time()
            )

        if protocol.ns.startswith(Namespace.ISO_V20_BASE):
            return MeterInfoV20(
                meter_id="Switch-Meter-123",
                charged_energy_reading_wh=10,
                meter_timestamp=time.time(),
            )

        logger.error(f"Unknown protocol {protocol}, can't determine MeterInfo type")
        raise InvalidProtocolError

    def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """Overrides EVSEControllerInterface.get_supported_providers()."""
        return None

    def set_hlc_charging(self, is_ongoing: bool) -> None:
        """Overrides EVSEControllerInterface.set_hlc_charging()."""
        pass

    def stop_charger(self) -> None:
        pass

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""
        return ACEVSEStatus(
            notification_max_delay=0, evse_notification=EVSENotification.NONE, rcd=False
        )

    def get_ac_evse_charge_parameter(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        )
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=0, value=32, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""
        return DCEVSEStatus(
            evse_notification=EVSENotification.NONE,
            notification_max_delay=0,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        )

    def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""
        return DCEVSEChargeParameter(
            dc_evse_status=DCEVSEStatus(
                notification_max_delay=100,
                evse_notification=EVSENotification.NONE,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_maximum_power_limit=PVEVSEMaxPowerLimit(
                multiplier=1, value=230, unit="W"
            ),
            evse_maximum_current_limit=PVEVSEMaxCurrentLimit(
                multiplier=1, value=4, unit="A"
            ),
            evse_maximum_voltage_limit=PVEVSEMaxVoltageLimit(
                multiplier=1, value=4, unit="V"
            ),
            evse_minimum_current_limit=PVEVSEMinCurrentLimit(
                multiplier=1, value=2, unit="A"
            ),
            evse_minimum_voltage_limit=PVEVSEMinVoltageLimit(
                multiplier=1, value=4, unit="V"
            ),
            evse_peak_current_ripple=PVEVSEPeakCurrentRipple(
                multiplier=1, value=4, unit="A"
            ),
        )

    def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        return PVEVSEPresentVoltage(multiplier=0, value=230, unit="V")

    def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        return PVEVSEPresentCurrent(multiplier=0, value=1, unit="A")

    def start_cable_check(self):
        pass

    def set_precharge(self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent):
        pass

    def send_charging_command(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        pass

    def is_evse_current_limit_achieved(self) -> bool:
        return True

    def is_evse_voltage_limit_achieved(self) -> bool:
        return True

    def is_evse_power_limit_achieved(self) -> bool:
        return True

    def get_evse_processing_state(self) -> EVSEProcessing:
        return EVSEProcessing.FINISHED

    def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        return PVEVSEMaxVoltageLimit(multiplier=0, value=600, unit="V")

    def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        return PVEVSEMaxCurrentLimit(multiplier=0, value=300, unit="A")

    def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        return PVEVSEMaxPowerLimit(multiplier=1, value=1000, unit="W")
