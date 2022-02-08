"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import logging
import time
from typing import List, Optional, Union

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.exceptions import InvalidProtocolError
from iso15118.shared.messages.enums import Namespace, Protocol
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EnergyTransferModeEnum,
    EVSENotification,
    IsolationLevel,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVSECurrentRegulationTolerance,
    PVEVSEEnergyToBeDelivered,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PMaxScheduleEntry,
    PMaxScheduleEntryDetails,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTupleEntry,
    UnitSymbol,
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

    def get_evse_id(self) -> str:
        """Overrides EVSEControllerInterface.get_evse_id()."""
        return "UK123E1234"

    def get_supported_energy_transfer_modes(self) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""
        ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        dc_extended = EnergyTransferModeEnum.DC_EXTENDED
        return [dc_extended]

    def is_authorised(self) -> bool:
        """Overrides EVSEControllerInterface.is_authorised()."""
        return True

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
        evse_maximum_current_limit = PVEVSEMaxCurrentLimit(
            multiplier=0, value=60, unit=UnitSymbol.AMPERE
        )
        evse_maximum_power_limit = PVEVSEMaxPowerLimit(
            multiplier=0, value=30000, unit=UnitSymbol.WATT
        )
        evse_maximum_voltage_limit = PVEVSEMaxVoltageLimit(
            multiplier=0, value=450, unit=UnitSymbol.VOLTAGE
        )
        evse_minimum_curren_limit = PVEVSEMinCurrentLimit(
            multiplier=0, value=5, unit=UnitSymbol.AMPERE
        )
        evse_minimum_voltage_limit = PVEVSEMinVoltageLimit(
            multiplier=0, value=250, unit=UnitSymbol.VOLTAGE
        )
        evse_peak_current_ripple = PVEVSEPeakCurrentRipple(
            multiplier=0, value=5, unit=UnitSymbol.AMPERE
        )
        evse_current_regulation_tolerance = PVEVSECurrentRegulationTolerance(
            multiplier=0, value=50, unit=UnitSymbol.AMPERE
        )
        evse_energy_to_be_delivered = PVEVSEEnergyToBeDelivered(
            multiplier=0, value=10000, unit=UnitSymbol.WATT_HOURS
        )

        return DCEVSEChargeParameter(
            dc_evse_status=self.get_dc_evse_status(),
            evse_maximum_current_limit=evse_maximum_current_limit,
            evse_maximum_power_limit=evse_maximum_power_limit,
            evse_maximum_voltage_limit=evse_maximum_voltage_limit,
            evse_minimum_current_limit=evse_minimum_curren_limit,
            evse_minimum_voltage_limit=evse_minimum_voltage_limit,
            evse_current_regulation_tolerance=evse_current_regulation_tolerance,  # optional
            evse_peak_current_ripple=evse_peak_current_ripple,
            evse_energy_to_be_delivered=evse_energy_to_be_delivered,  # optional
        )

    def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        return PVEVSEPresentVoltage(multiplier=0, value=230, unit="V")

    def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        return PVEVSEPresentCurrent(multiplier=0, value=10, unit="A")

    def set_ev_target_voltage(self, voltage):
        pass

    def set_ev_target_current(self, current):
        pass

    def set_cable_check(self):
        pass

    def set_precharge(self):
        pass

    def session_terminated(self):
        pass

    def set_ev_soc(self, soc):
        pass
