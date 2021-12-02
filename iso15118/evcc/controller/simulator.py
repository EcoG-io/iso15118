"""
This module contains a dummy implementation of the abstract class for an EVCC to
retrieve data from the EV. The DummyEVController overrides all abstract methods from
EVControllerInterface.
"""
import asyncio
import logging.config
from typing import List, Tuple, Optional

from iso15118.evcc.controller.interface import EVControllerInterface, ChargeParamsV2
from iso15118.shared import settings
from iso15118.shared.exceptions import InvalidProtocolError, MACAddressNotFound
from iso15118.shared.messages.enums import Protocol, Namespace
from iso15118.shared.messages.iso15118_2.datatypes import EnergyTransferModeEnum,\
    ACEVChargeParameter, PVEAmount, PVEVMaxVoltage, \
    PVEVMaxCurrent, PVEVMinCurrent, UnitSymbol, SAScheduleTuple, \
    ChargeProgress, ProfileEntry, PVPMax, ProfileEntryDetails
from iso15118.shared.messages.iso15118_20.ac import ACChargeParameterDiscoveryReqParams, \
    BPTACChargeParameterDiscoveryReqParams
from iso15118.shared.messages.iso15118_20.common_messages import EMAID
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.network import get_nic_mac_address

logging.config.fileConfig(fname=settings.LOGGER_CONF_PATH,
                          disable_existing_loggers=False)
logger = logging.getLogger(__name__)


class SimEVController(EVControllerInterface):
    """
    A simulated version of an EV controller
    """

    def __init__(self):
        self.charging_loop_cycles: int = 0

    def get_evcc_id(self, protocol: Protocol) -> str:
        """Overrides EVControllerInterface.get_evcc_id()."""
        from iso15118.evcc.evcc_settings import NETWORK_INTERFACE

        if protocol in (Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121):
            try:
                hex_str = get_nic_mac_address(NETWORK_INTERFACE)
                return hex_str.replace(':', '').upper()
            except MACAddressNotFound as exc:
                logger.warning("Couldn't determine EVCCID (ISO 15118-2) - "
                               f"Reason: {exc}. Setting MAC address to "
                               "'000000000000'")
                return '000000000000'
        elif protocol.ns.startswith(Namespace.ISO_V20_BASE):
            # The check digit (last character) is not a correctly computed one
            return "WMIV1234567890ABCDEX"
        else:
            logger.error(f"Invalid protocol '{protocol}', can't determine EVCCID")
            raise InvalidProtocolError

    def get_energy_transfer_mode(self) -> EnergyTransferModeEnum:
        """Overrides EVControllerInterface.get_energy_transfer_mode()."""
        return EnergyTransferModeEnum.AC_THREE_PHASE_CORE

    def get_charge_params_v2(self) -> ChargeParamsV2:
        """Overrides EVControllerInterface.get_charge_params_v2()."""
        # This is for simulating AC only. You can modify to simulate DC charging
        e_amount = PVEAmount(multiplier=0, value=60, unit=UnitSymbol.WATT_HOURS)
        ev_max_voltage = PVEVMaxVoltage(multiplier=0, value=400,
                                        unit=UnitSymbol.VOLTAGE)
        ev_max_current = PVEVMaxCurrent(multiplier=0, value=16,
                                        unit=UnitSymbol.AMPERE)
        ev_min_current = PVEVMinCurrent(multiplier=0, value=10,
                                        unit=UnitSymbol.AMPERE)
        ac_charge_params = ACEVChargeParameter(departure_time=0,
                                               e_amount=e_amount,
                                               ev_max_voltage=ev_max_voltage,
                                               ev_max_current=ev_max_current,
                                               ev_min_current=ev_min_current)
        return ChargeParamsV2(self.get_energy_transfer_mode(), ac_charge_params, None)

    def get_charge_params_v20(self) -> \
            Tuple[ACChargeParameterDiscoveryReqParams,
                  Optional[BPTACChargeParameterDiscoveryReqParams]]:
        """Overrides EVControllerInterface.get_charge_params_v20()."""
        ac_params = ACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=1, value=11),
            ev_min_charge_power=RationalNumber(exponent=0, value=10))

        bpt_ac_params = BPTACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=1, value=11),
            ev_min_charge_power=RationalNumber(exponent=0, value=10),
            ev_max_discharge_power=RationalNumber(exponent=1, value=11),
            ev_min_discharge_power=RationalNumber(exponent=0, value=10))

        # TODO Add support for DC and WPT
        return ac_params, bpt_ac_params

    def is_cert_install_needed(self) -> bool:
        """Overrides EVControllerInterface.is_cert_install_needed()."""
        return True

    def process_sa_schedules(self, sa_schedules: List[SAScheduleTuple]) \
            -> Tuple[ChargeProgress, int, List[ProfileEntry]]:
        """Overrides EVControllerInterface.process_sa_schedules()."""
        schedule = sa_schedules.pop()
        profile_entry_list: List[ProfileEntry] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for p_max_schedule_entry in schedule.tuple.p_max_schedule:
            schedule_entry_details = p_max_schedule_entry.entry_details
            profile_entry_details = ProfileEntryDetails(
                start=schedule_entry_details.time_interval.start,
                max_power=schedule_entry_details.p_max)
            profile_entry_list.append(
                ProfileEntry(entry_details=profile_entry_details))

            # The last PMaxSchedule element has an optional 'duration' field. if
            # 'duration' is present, then there'll be no more PMaxSchedule element
            # (with p_max set to 0 kW). Instead, the 'duration' informs how long the
            # current power level applies before the offered charging schedule ends.
            if schedule_entry_details.time_interval.duration:
                zero_power = PVPMax(multiplier=0, value=0, unit=UnitSymbol.WATT)
                last_profile_entry_details = ProfileEntryDetails(
                    start=(schedule_entry_details.time_interval.start +
                           schedule_entry_details.time_interval.duration),
                    max_power=zero_power)
                profile_entry_list.append(
                    ProfileEntry(entry_details=last_profile_entry_details))

        # TODO If a SalesTariff is present and digitally signed (and TLS is used),
        #      verify each sales tariff with the mobility operator sub 2 certificate

        return ChargeProgress.START, \
               schedule.tuple.sa_schedule_tuple_id, \
               profile_entry_list

    def continue_charging(self) -> bool:
        """Overrides EVControllerInterface.continue_charging()."""
        if self.charging_loop_cycles == 10:
            # To simulate a bit of a charging loop, we'll let it run 10 times
            return False
        else:
            self.charging_loop_cycles += 1
            asyncio.sleep(0.5)
            return True

    def store_contract_cert_and_priv_key(self, contract_cert: bytes, priv_key: bytes):
        """Overrides EVControllerInterface.store_contract_cert_and_priv_key()."""
        # TODO Need to store the contract cert and private key
        pass

    def get_prioritised_emaids(self) -> Optional[List[EMAID]]:
        return None
