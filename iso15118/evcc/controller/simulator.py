"""
This module contains a dummy implementation of the abstract class for an EVCC to
retrieve data from the EV. The DummyEVController overrides all abstract methods from
EVControllerInterface.
"""
import logging
from typing import List, Optional, Tuple

from iso15118.shared.messages.datatypes_iso15118_2_dinspec import (
    PVEVTargetVoltage,
    PVEVTargetCurrent,
    PVEAmount,
    PVEVMaxVoltage,
    PVEVMaxCurrent,
    PVEVMinCurrent,
    PVPMax,
    PVEVMaxCurrentLimit,
    PVEVMaxVoltageLimit,
    DCEVChargeParams,
    PVEVMaxPowerLimit,
    PVEVEnergyCapacity,
    PVEVEnergyRequest,
    PVRemainingTimeToFullSOC,
    PVRemainingTimeToBulkSOC,
    PVEVSEPresentVoltage,
)
from iso15118.shared.messages.din_spec.datatypes import (
    DCEVStatus as DCEVStatusDINSPEC,
    DCEVPowerDeliveryParameter,
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
    ProfileEntryDetails as ProfileEntryDetailsDINSPEC,
)

from iso15118.evcc.controller.interface import (
    ChargeParamsV2,
    EVControllerInterface,
)
from iso15118.shared.exceptions import InvalidProtocolError, MACAddressNotFound
from iso15118.shared.messages.enums import (
    Namespace,
    Protocol,
    EnergyTransferModeEnum,
    UnitSymbol,
    DCEVErrorCode,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVChargeParameter,
    ChargeProgress,
    ChargingProfile,
    ProfileEntryDetails,
    SAScheduleTupleEntry,
    DCEVChargeParameter,
)
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryReqParams,
    BPTACChargeParameterDiscoveryReqParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import EMAIDList
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.network import get_nic_mac_address

logger = logging.getLogger(__name__)


class SimEVController(EVControllerInterface):
    """
    A simulated version of an EV controller
    """

    def __init__(self):
        self.charging_loop_cycles: int = 0
        self.precharge_loop_cycles: int = 0
        self._charging_is_completed = False
        self._soc = 10

        self.dc_ev_charge_params: DCEVChargeParams = DCEVChargeParams(
            dc_max_current_limit=PVEVMaxCurrentLimit(
                multiplier=-3, value=32000, unit=UnitSymbol.AMPERE
            ),
            dc_max_power_limit=PVEVMaxPowerLimit(
                multiplier=1, value=8000, unit=UnitSymbol.WATT
            ),
            dc_max_voltage_limit=PVEVMaxVoltageLimit(
                multiplier=1, value=40, unit=UnitSymbol.VOLTAGE
            ),
            dc_energy_capacity=PVEVEnergyCapacity(
                multiplier=1, value=7000, unit=UnitSymbol.WATT_HOURS
            ),
            dc_target_current=PVEVTargetCurrent(
                multiplier=0, value=1, unit=UnitSymbol.AMPERE
            ),
            dc_target_voltage=PVEVTargetVoltage(
                multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
            ),
        )

    def get_evcc_id(self, protocol: Protocol, iface: str) -> str:
        """Overrides EVControllerInterface.get_evcc_id()."""

        if protocol == Protocol.ISO_15118_2 or protocol == Protocol.DIN_SPEC_70121:
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

    def get_energy_transfer_mode(self, protocol: Protocol) -> EnergyTransferModeEnum:
        """Overrides EVControllerInterface.get_energy_transfer_mode()."""
        if protocol == Protocol.DIN_SPEC_70121:
            return EnergyTransferModeEnum.DC_EXTENDED
        return EnergyTransferModeEnum.AC_THREE_PHASE_CORE

    def is_energy_transfer_mode_ac(self, protocol: Protocol) -> bool:
        if self.get_energy_transfer_mode(protocol).startswith("AC_"):
            return True
        return False

    def get_charge_params_v2(self, protocol: Protocol) -> ChargeParamsV2:
        """Overrides EVControllerInterface.get_charge_params_v2()."""
        ac_charge_params = None
        dc_charge_params = None

        if self.is_energy_transfer_mode_ac(protocol):
            e_amount = PVEAmount(multiplier=0, value=60, unit=UnitSymbol.WATT_HOURS)
            ev_max_voltage = PVEVMaxVoltage(
                multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
            )
            ev_max_current = PVEVMaxCurrent(
                multiplier=-3, value=32000, unit=UnitSymbol.AMPERE
            )
            ev_min_current = PVEVMinCurrent(
                multiplier=0, value=10, unit=UnitSymbol.AMPERE
            )
            ac_charge_params = ACEVChargeParameter(
                departure_time=0,
                e_amount=e_amount,
                ev_max_voltage=ev_max_voltage,
                ev_max_current=ev_max_current,
                ev_min_current=ev_min_current,
            )
        else:
            ev_energy_request = PVEVEnergyRequest(
                multiplier=1, value=6000, unit=UnitSymbol.WATT_HOURS
            )
            dc_charge_params = DCEVChargeParameter(
                departure_time=0,
                dc_ev_status=self.get_dc_ev_status(),
                ev_maximum_current_limit=self.dc_ev_charge_params.dc_max_current_limit,
                ev_maximum_power_limit=self.dc_ev_charge_params.dc_max_power_limit,
                ev_maximum_voltage_limit=self.dc_ev_charge_params.dc_max_voltage_limit,
                ev_energy_capacity=self.dc_ev_charge_params.dc_energy_capacity,
                ev_energy_request=ev_energy_request,
                full_soc=90,
                bulk_soc=80,
            )
        return ChargeParamsV2(
            self.get_energy_transfer_mode(protocol), ac_charge_params, dc_charge_params
        )

    def get_charge_params_v20(
        self,
    ) -> Tuple[
        ACChargeParameterDiscoveryReqParams,
        Optional[BPTACChargeParameterDiscoveryReqParams],
    ]:
        """Overrides EVControllerInterface.get_charge_params_v20()."""
        ac_params = ACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=1, value=11),
            ev_min_charge_power=RationalNumber(exponent=0, value=10),
        )

        bpt_ac_params = BPTACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber(exponent=1, value=11),
            ev_min_charge_power=RationalNumber(exponent=0, value=10),
            ev_max_discharge_power=RationalNumber(exponent=1, value=11),
            ev_min_discharge_power=RationalNumber(exponent=0, value=10),
        )

        # TODO Add support for DC and WPT
        return ac_params, bpt_ac_params

    def is_cert_install_needed(self) -> bool:
        """Overrides EVControllerInterface.is_cert_install_needed()."""
        return True

    def process_sa_schedules_dinspec(
        self, sa_schedules: List[SAScheduleTupleEntryDINSPEC]
    ) -> int:
        """Overrides EVControllerInterface.process_sa_schedules_dinspec()."""
        schedule = sa_schedules.pop()
        profile_entry_list: List[ProfileEntryDetailsDINSPEC] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for schedule_entry_details in schedule.p_max_schedule.entry_details:
            profile_entry_details = ProfileEntryDetailsDINSPEC(
                start=schedule_entry_details.time_interval.start,
                max_power=schedule_entry_details.p_max,
            )
            profile_entry_list.append(profile_entry_details)

            # The last PMaxSchedule element has an optional 'duration' field. if
            # 'duration' is present, then there'll be no more PMaxSchedule element
            # (with p_max set to 0 kW). Instead, the 'duration' informs how long the
            # current power level applies before the offered charging schedule ends.
            if schedule_entry_details.time_interval.duration:
                zero_power = 1
                last_profile_entry_details = ProfileEntryDetailsDINSPEC(
                    start=(
                        schedule_entry_details.time_interval.start
                        + schedule_entry_details.time_interval.duration
                    ),
                    max_power=zero_power,
                )
                profile_entry_list.append(last_profile_entry_details)

        return schedule.sa_schedule_tuple_id

    def process_sa_schedules(
        self, sa_schedules: List[SAScheduleTupleEntry]
    ) -> Tuple[ChargeProgress, int, ChargingProfile]:
        """Overrides EVControllerInterface.process_sa_schedules()."""
        schedule = sa_schedules.pop()
        profile_entry_list: List[ProfileEntryDetails] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for schedule_entry_details in schedule.p_max_schedule.entry_details:
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
            schedule.sa_schedule_tuple_id,
            ChargingProfile(profile_entries=profile_entry_list),
        )

    def continue_charging(self) -> bool:
        """Overrides EVControllerInterface.continue_charging()."""
        if self.charging_loop_cycles == 10 or self.is_charging_complete():
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

    def get_dc_charge_params(self) -> DCEVChargeParams:
        return self.dc_ev_charge_params

    def get_dc_ev_status(self) -> DCEVStatusDINSPEC:
        return DCEVStatusDINSPEC(
            ev_ready=True,
            ev_error_code=DCEVErrorCode.NO_ERROR,
            ev_ress_soc=60,
        )

    def ready_to_charge(self) -> bool:
        return self.continue_charging()

    def is_precharged(self, present_voltage_evse: PVEVSEPresentVoltage) -> bool:
        return True

    def get_dc_ev_power_delivery_parameter(self) -> DCEVPowerDeliveryParameter:
        return DCEVPowerDeliveryParameter(
            dc_ev_status=self.get_dc_ev_status(),
            bulk_charging_complete=False,
            charging_complete=self.continue_charging(),
        )

    def get_bulk_charging_complete(self) -> bool:
        return False

    def is_charging_complete(self) -> bool:
        if self._soc == 100:
            return True
        else:
            return False

    def get_remaining_time_to_full_soc(self) -> PVRemainingTimeToFullSOC:
        return PVRemainingTimeToFullSOC(multiplier=0, value=100, unit="s")

    def get_remaining_time_to_bulk_soc(self) -> PVRemainingTimeToBulkSOC:
        return PVRemainingTimeToBulkSOC(multiplier=0, value=80, unit="s")

    def welding_detection_has_finished(self):
        return True
