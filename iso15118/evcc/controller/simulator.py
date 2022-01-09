"""
This module contains a dummy implementation of the abstract class for an EVCC to
retrieve data from the EV. The DummyEVController overrides all abstract methods from
EVControllerInterface.
"""
import logging
import random
from typing import List, Optional, Tuple

from iso15118.evcc.controller.interface import ChargeParamsV2, EVControllerInterface
from iso15118.shared.exceptions import InvalidProtocolError, MACAddressNotFound
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVChargeParameter,
    ChargingProfile,
    EnergyTransferModeEnum,
    ProfileEntryDetails,
    PVEAmount,
    PVEVMaxCurrent,
    PVEVMaxVoltage,
    PVEVMinCurrent,
    PVPMax,
    SAScheduleTuple,
    UnitSymbol,
)
from iso15118.shared.messages.enums import (
    Namespace,
    Protocol,
    ServiceV20,
    PriceAlgorithm,
)
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryReqParams,
    BPTACChargeParameterDiscoveryReqParams, ScheduledACChargeLoopReqParams,
    BPTScheduledACChargeLoopReqParams, DynamicACChargeLoopReqParams,
    BPTDynamicACChargeLoopReqParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    EMAIDList,
    ParameterSet as ParameterSetV20,
    ScheduledScheduleExchangeReqParams,
    DynamicScheduleExchangeReqParams,
    EVEnergyOffer,
    EVPowerSchedule,
    EVPowerScheduleEntryList,
    EVAbsolutePriceSchedule,
    EVPowerScheduleEntry,
    EVPriceRuleStackList,
    EVPriceRuleStack,
    EVPriceRule,
    SelectedEnergyService,
    SelectedVAS,
    ScheduledScheduleExchangeResParams,
    DynamicScheduleExchangeResParams,
    EVPowerProfile,
    ChargeProgress, ScheduledEVPowerProfile, PowerToleranceAcceptance,
    DynamicEVPowerProfile,
)
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.messages.iso15118_20.dc import (
    DCChargeParameterDiscoveryReqParams,
    BPTDCChargeParameterDiscoveryReqParams,
)
from iso15118.shared.network import get_nic_mac_address

logger = logging.getLogger(__name__)


class SimEVController(EVControllerInterface):
    """
    A simulated version of an EV controller
    """

    def __init__(self):
        self.charging_loop_cycles: int = 0

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    def get_evcc_id(self, protocol: Protocol, iface: str) -> str:
        """Overrides EVControllerInterface.get_evcc_id()."""

        if protocol in (Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121):
            try:
                hex_str = get_nic_mac_address(iface)
                return hex_str.replace(":", "").upper()
            except MACAddressNotFound as exc:
                logger.warning(
                    "Couldn't determine EVCCID (ISO 15118-2) - "
                    f"Reason: {exc}. Setting MAC address to "
                    "'000000000000'"
                )
                return "000000000000"
        elif protocol.ns.startswith(Namespace.ISO_V20_BASE):
            # The check digit (last character) is not a correctly computed one
            return "WMIV1234567890ABCDEX"
        else:
            logger.error(f"Invalid protocol '{protocol}', can't determine EVCCID")
            raise InvalidProtocolError

    def get_energy_transfer_mode(self) -> EnergyTransferModeEnum:
        """Overrides EVControllerInterface.get_energy_transfer_mode()."""
        return EnergyTransferModeEnum.AC_THREE_PHASE_CORE

    def get_energy_service(self) -> ServiceV20:
        """Overrides EVControllerInterface.get_energy_transfer_service()."""
        return ServiceV20.AC

    def select_energy_service_v20(
        self, service: ServiceV20, is_free: bool, parameter_sets: List[ParameterSetV20]
    ) -> SelectedEnergyService:
        """Overrides EVControllerInterface.select_energy_service_v20()."""
        selected_service = SelectedEnergyService(
            service=ServiceV20.get_by_id(service.service_id),
            is_free=is_free,
            parameter_set=parameter_sets.pop(),
        )
        return selected_service

    def select_vas_v20(
        self, service: ServiceV20, is_free: bool, parameter_sets: List[ParameterSetV20]
    ) -> Optional[SelectedVAS]:
        """Overrides EVControllerInterface.select_vas_v20()."""
        selected_service = SelectedVAS(
            service=ServiceV20.get_by_id(service.service_id),
            is_free=is_free,
            parameter_set=parameter_sets.pop(),
        )
        return selected_service

    def get_scheduled_se_params(
        self, selected_energy_service: SelectedEnergyService
    ) -> ScheduledScheduleExchangeReqParams:
        """Overrides EVControllerInterface.get_scheduled_se_params()."""
        ev_price_rule = EVPriceRule(
            energy_fee=RationalNumber(exponent=0, value=0),
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        ev_price_rule_stack = EVPriceRuleStack(
            duration=0, ev_price_rules=[ev_price_rule]
        )

        ev_price_rule_stack_list = EVPriceRuleStackList(
            ev_price_rule_stacks=[ev_price_rule_stack]
        )

        ev_absolute_price_schedule = EVAbsolutePriceSchedule(
            time_anchor=0,
            currency="EUR",
            price_algorithm=PriceAlgorithm.POWER,
            ev_price_rule_stacks=ev_price_rule_stack_list,
        )

        ev_power_schedule_entry = EVPowerScheduleEntry(
            duration=3600, power=RationalNumber(exponent=3, value=-10)
        )

        ev_power_schedule_entries = EVPowerScheduleEntryList(
            ev_power_schedule_entries=[ev_power_schedule_entry]
        )

        ev_power_schedule = EVPowerSchedule(
            time_anchor=0, ev_power_schedule_entries=ev_power_schedule_entries
        )

        energy_offer = EVEnergyOffer(
            ev_power_schedule=ev_power_schedule,
            ev_absolute_price_schedule=ev_absolute_price_schedule,
        )

        scheduled_params = ScheduledScheduleExchangeReqParams(
            departure_time=7200,
            ev_target_energy_request=RationalNumber(exponent=3, value=10),
            ev_max_energy_request=RationalNumber(exponent=3, value=20),
            ev_min_energy_request=RationalNumber(exponent=3, value=5),
            energy_offer=energy_offer,
        )

        return scheduled_params

    def get_dynamic_se_params(
        self, selected_energy_service: SelectedEnergyService
    ) -> DynamicScheduleExchangeReqParams:
        """Overrides EVControllerInterface.get_dynamic_se_params()."""
        dynamic_params = DynamicScheduleExchangeReqParams(
            departure_time=7200,
            min_soc=30,
            target_soc=80,
            ev_target_energy_request=RationalNumber(exponent=3, value=40),
            ev_max_energy_request=RationalNumber(exponent=1, value=6000),
            ev_min_energy_request=RationalNumber(exponent=0, value=20000),
            ev_max_v2x_energy_request=RationalNumber(exponent=0, value=5000),
            ev_min_v2x_energy_request=RationalNumber(exponent=0, value=0),
        )

        return dynamic_params

    def process_scheduled_se_params(
            self,
            scheduled_params: ScheduledScheduleExchangeResParams,
            pause: bool
    ) -> Tuple[Optional[EVPowerProfile], ChargeProgress]:
        """Overrides EVControllerInterface.process_scheduled_se_params()."""
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Scheduled parameters for ScheduleExchangeReq not yet ready")
            return None, ChargeProgress.SCHEDULE_RENEGOTIATION

        charge_progress = ChargeProgress.START

        if pause:
            charge_progress = ChargeProgress.STOP

        # Let's just select the first schedule offered
        selected_schedule = scheduled_params.schedule_tuples.pop()
        charging_schedule = selected_schedule.charging_schedule.power_schedule
        charging_schedule_entries = charging_schedule.schedule_entry_list.entries

        # We just copy the values from the charging schedule into the EV power profile
        ev_power_schedule_entries: List[EVPowerScheduleEntry] = []
        for entry in charging_schedule_entries:
            ev_power_schedule_entry = EVPowerScheduleEntry(
                duration=entry.duration,
                power=entry.power
            )
            ev_power_schedule_entries.append(ev_power_schedule_entry)

        ev_power_profile_entry_list = EVPowerScheduleEntryList(
            entries=ev_power_schedule_entries
        )

        scheduled_profile = ScheduledEVPowerProfile(
            selected_schedule_tuple_id=selected_schedule.schedule_tuple_id,
            power_tolerance_acceptance=PowerToleranceAcceptance.CONFIRMED
        )

        ev_power_profile = EVPowerProfile(
            time_anchor=0,
            entry_list=ev_power_profile_entry_list,
            scheduled_profile=scheduled_profile
        )

        return ev_power_profile, charge_progress

    def process_dynamic_se_params(
            self,
            dynamic_params: DynamicScheduleExchangeResParams,
            pause: bool
    ) -> Tuple[Optional[EVPowerProfile], ChargeProgress]:
        """Overrides EVControllerInterface.process_dynamic_se_params()."""
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Dynamic parameters for ScheduleExchangeReq not yet ready")
            return None, ChargeProgress.SCHEDULE_RENEGOTIATION

        charge_progress = ChargeProgress.START

        if pause:
            charge_progress = ChargeProgress.STOP

        ev_power_schedule_entry = EVPowerScheduleEntry(
            duration=3600,
            power=RationalNumber(exponent=0, value=11000)
        )

        ev_power_profile_entry_list = EVPowerScheduleEntryList(
            entries=[ev_power_schedule_entry]
        )

        ev_power_profile = EVPowerProfile(
            time_anchor=0,
            entry_list=ev_power_profile_entry_list,
            dynamic_profile=DynamicEVPowerProfile()
        )

        return ev_power_profile, charge_progress

    def is_cert_install_needed(self) -> bool:
        """Overrides EVControllerInterface.is_cert_install_needed()."""
        return False

    def process_sa_schedules_v2(
        self, sa_schedules: List[SAScheduleTuple]
    ) -> Tuple[ChargeProgress, int, ChargingProfile]:
        """Overrides EVControllerInterface.process_sa_schedules()."""
        schedule = sa_schedules.pop()
        profile_entry_list: List[ProfileEntryDetails] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for schedule_entry_details in schedule.p_max_schedule.schedule_entries:
            profile_entry_details = ProfileEntryDetails(
                start=schedule_entry_details.time_interval.start,
                max_power=schedule_entry_details.p_max,
            )
            profile_entry_list.append(profile_entry_details)

            # The last PMaxSchedule element has an optional 'duration' field. if
            # 'duration' is present, then there'll be no more PMaxSchedule element
            # (with p_max set to 0 kW). Instead, the 'duration' informs how long the
            # current power level applies before the offered charging schedule ends.
            if schedule_entry_details.time_interval.duration:
                zero_power = PVPMax(multiplier=0, value=0, unit=UnitSymbol.WATT)
                last_profile_entry_details = ProfileEntryDetails(
                    start=(
                        schedule_entry_details.time_interval.start
                        + schedule_entry_details.time_interval.duration
                    ),
                    max_power=zero_power,
                )
                profile_entry_list.append(last_profile_entry_details)

        # TODO If a SalesTariff is present and digitally signed (and TLS is used),
        #      verify each sales tariff with the mobility operator sub 2 certificate

        return (
            ChargeProgress.START,
            schedule.tuple_id,
            ChargingProfile(profile_entries=profile_entry_list),
        )

    def continue_charging(self) -> bool:
        """Overrides EVControllerInterface.continue_charging()."""
        if self.charging_loop_cycles == 10:
            # To simulate a bit of a charging loop, we'll let it run 10 times
            return False
        else:
            self.charging_loop_cycles += 1
            # The line below can just be called once process_message in all states
            # are converted to async calls
            # await asyncio.sleep(0.5)
            return True

    def store_contract_cert_and_priv_key(self, contract_cert: bytes, priv_key: bytes):
        """Overrides EVControllerInterface.store_contract_cert_and_priv_key()."""
        # TODO Need to store the contract cert and private key
        pass

    def get_prioritised_emaids(self) -> Optional[EMAIDList]:
        return None

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_ac_charge_params_v2(self) -> ChargeParamsV2:
        """Overrides EVControllerInterface.get_ac_charge_params_v2()."""
        e_amount = PVEAmount(multiplier=0, value=60, unit=UnitSymbol.WATT_HOURS)
        ev_max_voltage = PVEVMaxVoltage(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        )
        ev_max_current = PVEVMaxCurrent(
            multiplier=-3, value=32000, unit=UnitSymbol.AMPERE
        )
        ev_min_current = PVEVMinCurrent(multiplier=0, value=10, unit=UnitSymbol.AMPERE)
        ac_charge_params = ACEVChargeParameter(
            departure_time=0,
            e_amount=e_amount,
            ev_max_voltage=ev_max_voltage,
            ev_max_current=ev_max_current,
            ev_min_current=ev_min_current,
        )
        return ChargeParamsV2(self.get_energy_transfer_mode(), ac_charge_params, None)

    def get_ac_charge_params_v20(self) -> ACChargeParameterDiscoveryReqParams:
        """Overrides EVControllerInterface.get_ac_charge_params_v20()."""
        return ACChargeParameterDiscoveryReqParams(
                ev_max_charge_power=RationalNumber(exponent=3, value=3),
                ev_max_charge_power_l2=RationalNumber(exponent=3, value=3),
                ev_max_charge_power_l3=RationalNumber(exponent=3, value=3),
                ev_min_charge_power=RationalNumber(exponent=0, value=100),
                ev_min_charge_power_l2=RationalNumber(exponent=0, value=100),
                ev_min_charge_power_l3=RationalNumber(exponent=0, value=100)
            )

    def get_ac_bpt_charge_params_v20(self) -> BPTACChargeParameterDiscoveryReqParams:
        """Overrides EVControllerInterface.get_bpt_ac_charge_params_v20()."""
        return BPTACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=3, value=11),
            ev_min_charge_power=RationalNumber(exponent=0, value=100),
            ev_max_discharge_power=RationalNumber(exponent=3, value=11),
            ev_min_discharge_power=RationalNumber(exponent=0, value=100),
        )

    def get_scheduled_ac_charge_loop_params(self) -> ScheduledACChargeLoopReqParams:
        """Overrides EVControllerInterface.get_scheduled_ac_charge_loop_params()."""
        return ScheduledACChargeLoopReqParams(
            ev_present_active_power=RationalNumber(exponent=3, value=200),
            # Add more optional fields if wanted
        )

    def get_bpt_scheduled_ac_charge_loop_params(
            self
    ) -> BPTScheduledACChargeLoopReqParams:
        """Overrides EVControllerInterface.get_bpt_scheduled_ac_charge_loop_params()."""
        return BPTScheduledACChargeLoopReqParams(
            ev_present_active_power=RationalNumber(exponent=3, value=200),
            # Add more optional fields if wanted
        )

    def get_dynamic_ac_charge_loop_params(self) -> DynamicACChargeLoopReqParams:
        """Overrides EVControllerInterface.get_dynamic_ac_charge_loop_params()."""
        return DynamicACChargeLoopReqParams(
            ev_target_energy_request=RationalNumber(exponent=3, value=40),
            ev_max_energy_request=RationalNumber(exponent=3, value=60),
            ev_min_energy_request=RationalNumber(exponent=3, value=20),
            ev_max_charge_power=RationalNumber(exponent=3, value=300),
            ev_min_charge_power=RationalNumber(exponent=0, value=100),
            ev_present_active_power=RationalNumber(exponent=3, value=200),
            ev_present_reactive_power=RationalNumber(exponent=3, value=20),
            # Add more optional fields if wanted
        )

    def get_bpt_dynamic_ac_charge_loop_params(self) -> BPTDynamicACChargeLoopReqParams:
        """Overrides EVControllerInterface.get_bpt_dynamic_ac_charge_loop_params()."""
        return BPTDynamicACChargeLoopReqParams(
            ev_target_energy_request=RationalNumber(exponent=3, value=40),
            ev_max_energy_request=RationalNumber(exponent=3, value=60),
            ev_min_energy_request=RationalNumber(exponent=3, value=20),
            ev_max_charge_power=RationalNumber(exponent=3, value=300),
            ev_min_charge_power=RationalNumber(exponent=0, value=100),
            ev_present_active_power=RationalNumber(exponent=3, value=200),
            ev_present_reactive_power=RationalNumber(exponent=3, value=20),
            ev_max_discharge_power=RationalNumber(exponent=3, value=11),
            ev_min_discharge_power=RationalNumber(exponent=3, value=1),
            # Add more optional fields if wanted
        )

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_dc_charge_params_v2(self) -> ChargeParamsV2:
        """Overrides EVControllerInterface.get_dc_charge_params_v2()."""
        raise NotImplementedError(
            "DC charge parameters for ISO 15118-2 not yet impmlemented"
        )

    def get_dc_charge_params_v20(self) -> DCChargeParameterDiscoveryReqParams:
        """Overrides EVControllerInterface.get_dc_charge_params_v20()."""
        return DCChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=3, value=300),
            ev_min_charge_power=RationalNumber(exponent=0, value=100),
            ev_max_charge_current=RationalNumber(exponent=0, value=300),
            ev_min_charge_current=RationalNumber(exponent=0, value=10),
            ev_max_voltage=RationalNumber(exponent=0, value=1000),
            ev_min_voltage=RationalNumber(exponent=0, value=10),
        )

    def get_dc_bpt_charge_params_v20(self) -> BPTDCChargeParameterDiscoveryReqParams:
        """Overrides EVControllerInterface.get_bpt_dc_charge_params_v20()."""
        return BPTDCChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=3, value=300),
            ev_min_charge_power=RationalNumber(exponent=0, value=100),
            ev_max_charge_current=RationalNumber(exponent=0, value=300),
            ev_min_charge_current=RationalNumber(exponent=0, value=10),
            ev_max_voltage=RationalNumber(exponent=0, value=1000),
            ev_min_oltage=RationalNumber(exponent=0, value=10),
            ev_max_discharge_power=RationalNumber(exponent=3, value=11),
            ev_min_discharge_power=RationalNumber(exponent=3, value=1),
            ev_max_discharge_current=RationalNumber(exponent=0, value=11),
            ev_min_discharge_current=RationalNumber(exponent=0, value=0),
        )
