"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import logging
import random
import time
from typing import List, Optional, Union

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.exceptions import InvalidProtocolError
from iso15118.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
)
from iso15118.shared.messages.din_spec.datatypes import (
    PMaxScheduleEntry as PMaxScheduleEntryDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    PMaxScheduleEntryDetails as PMaxScheduleEntryDetailsDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    RelativeTimeInterval as RelativeTimeIntervalDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from iso15118.shared.messages.enums import (
    EnergyTransferModeEnum,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    MeterInfo as MeterInfoV2,
    PMaxSchedule,
)
    PMaxScheduleEntry,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from iso15118.shared.messages.enums import (
    Namespace,
    Protocol,
    ServiceV20,
    ParameterName,
    ControlMode,
    DCConnector,
    MobilityNeedsMode,
    Pricing,
    PriceAlgorithm,
)
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ProviderID,
    Service,
    ServiceList,
    ServiceParameterList,
    ParameterSet,
    Parameter,
    SelectedEnergyService,
    ScheduledScheduleExchangeResParams,
    DynamicScheduleExchangeResParams,
    ScheduleTuple,
    ChargingSchedule,
    PowerSchedule,
    AbsolutePriceSchedule,
    PowerScheduleEntryList,
    PowerScheduleEntry,
    TaxRuleList,
    PriceRuleStackList,
    OverstayRuleList,
    AdditionalServiceList,
    TaxRule,
    PriceRuleStack,
    PriceRule,
    OverstayRule,
    AdditionalService,
    PriceLevelSchedule,
    PriceLevelScheduleEntryList,
    PriceLevelScheduleEntry,
    ScheduleExchangeReq,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    MeterInfo as MeterInfoV20,
    RationalNumber,
)
from iso15118.shared.messages.iso15118_20.dc import (
    DCChargeParameterDiscoveryResParams,
    BPTDCChargeParameterDiscoveryResParams,
)

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
            """
            For DIN SPEC, only DC_CORE and DC_EXTENDED are supported.
            The other DC modes DC_COMBO_CORE and DC_DUAL are out of scope for DIN SPEC
            """
            dc_extended = EnergyTransferModeEnum.DC_EXTENDED
            return [dc_extended]

        # ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        # ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        dc_extended = EnergyTransferModeEnum.DC_EXTENDED
        return [dc_extended]

    def get_charge_params_v20(
        self, selected_service: SelectedEnergyService
    ) -> Union[
        ACChargeParameterDiscoveryResParams,
        BPTACChargeParameterDiscoveryResParams,
        DCChargeParameterDiscoveryResParams,
        BPTDCChargeParameterDiscoveryResParams,
    ]:
        """Overrides EVSEControllerInterface.get_charge_params_v20()."""
        if selected_service.service == ServiceV20.AC:
            return ACChargeParameterDiscoveryResParams(
                ev_max_charge_power=RationalNumber(exponent=3, value=11),
                ev_min_charge_power=RationalNumber(exponent=0, value=100),
            )
        elif selected_service.service == ServiceV20.AC_BPT:
            return BPTACChargeParameterDiscoveryResParams(
                ev_max_charge_power=RationalNumber(exponent=3, value=11),
                ev_min_charge_power=RationalNumber(exponent=0, value=100),
                ev_max_discharge_power=RationalNumber(exponent=3, value=11),
                ev_min_discharge_power=RationalNumber(exponent=0, value=100),
            )
        elif selected_service.service == ServiceV20.DC:
            return DCChargeParameterDiscoveryResParams(
                evse_max_charge_power=RationalNumber(exponent=3, value=300),
                evse_min_charge_power=RationalNumber(exponent=0, value=100),
                evse_max_charge_current=RationalNumber(exponent=0, value=300),
                evse_min_charge_current=RationalNumber(exponent=0, value=10),
                evse_max_voltage=RationalNumber(exponent=0, value=1000),
                evse_min_voltage=RationalNumber(exponent=0, value=10),
            )
        elif selected_service.service == ServiceV20.DC_BPT:
            return BPTDCChargeParameterDiscoveryResParams(
                evse_max_charge_power=RationalNumber(exponent=3, value=300),
                evse_min_charge_power=RationalNumber(exponent=0, value=100),
                evse_max_charge_current=RationalNumber(exponent=0, value=300),
                evse_min_charge_current=RationalNumber(exponent=0, value=10),
                evse_max_voltage=RationalNumber(exponent=0, value=1000),
                evse_min_oltage=RationalNumber(exponent=0, value=10),
                evse_max_discharge_power=RationalNumber(exponent=3, value=11),
                evse_min_discharge_power=RationalNumber(exponent=3, value=1),
                evse_max_discharge_current=RationalNumber(exponent=0, value=11),
                evse_min_discharge_current=RationalNumber(exponent=0, value=0),
            )
        else:
            # TODO Implement the remaining energy transer services
            logger.error("Energy transfer service not supported")

    def get_scheduled_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Optional[ScheduledScheduleExchangeResParams]:
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Scheduled parameters for ScheduleExchangeRes not yet ready")
            return None

        """Overrides EVSEControllerInterface.get_scheduled_se_params()."""
        charging_power_schedule_entry = PowerScheduleEntry(
            duration=3600,
            power=RationalNumber(exponent=3, value=10)
            # Check if AC ThreePhase applies (Connector parameter within parameter set
            # of SelectedEnergyService) if you want to add power_l2 and power_l3 values
        )

        charging_power_schedule = PowerSchedule(
            time_anchor=0,
            available_energy=RationalNumber(exponent=3, value=300),
            power_tolerance=RationalNumber(exponent=0, value=2000),
            power_schedule_entries=PowerScheduleEntryList(
                power_schedule_entries=[charging_power_schedule_entry]
            ),
        )

        tax_rule = TaxRule(
            tax_rule_id=1,
            tax_rule_name="What a great tax rule",
            tax_rate=RationalNumber(exponent=0, value=10),
            tax_included_in_price=False,
            applies_to_energy_fee=True,
            applies_to_parking_fee=True,
            applies_to_overstay_fee=True,
            applies_to_min_max_cost=True,
        )

        tax_rules = TaxRuleList(tax_rule=[tax_rule])

        price_rule = PriceRule(
            energy_fee=RationalNumber(exponent=0, value=20),
            parking_fee=RationalNumber(exponent=0, value=0),
            parking_fee_period=0,
            carbon_dioxide_emission=0,
            renewable_generation_percentage=0,
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        price_rule_stack = PriceRuleStack(duration=3600, price_rules=[price_rule])

        price_rule_stacks = PriceRuleStackList(price_rule_stacks=[price_rule_stack])

        overstay_rule = OverstayRule(
            description="What a great description",
            start_time=0,
            fee=RationalNumber(exponent=0, value=50),
            fee_period=3600,
        )

        overstay_rules = OverstayRuleList(
            time_shreshold=3600,
            power_threshold=RationalNumber(exponent=3, value=30),
            rules=[overstay_rule],
        )

        additional_service = AdditionalService(
            service_name="What a great service name",
            service_fee=RationalNumber(exponent=0, value=0),
        )

        additional_services = AdditionalServiceList(
            additional_services=[additional_service]
        )

        charging_absolute_price_schedule = AbsolutePriceSchedule(
            currency="EUR",
            language="ENG",
            price_algorithm=PriceAlgorithm.POWER,
            min_cost=RationalNumber(exponent=0, value=1),
            max_cost=RationalNumber(exponent=0, value=10),
            tax_rules=tax_rules,
            price_rule_stacks=price_rule_stacks,
            overstay_rules=overstay_rules,
            additional_services=additional_services,
        )

        discharging_power_schedule = PowerSchedule(
            duration=3600,
            power=RationalNumber(exponent=3, value=-5)
            # Check if AC ThreePhase applies (Connector parameter within parameter set
            # of SelectedEnergyService) if you want to add power_l2 and power_l3 values
        )

        discharging_absolute_price_schedule = charging_absolute_price_schedule

        charging_schedule = ChargingSchedule(
            power_schedule=charging_power_schedule,
            absolute_price_schedule=charging_absolute_price_schedule,
        )

        discharging_schedule = ChargingSchedule(
            power_schedule=discharging_power_schedule,
            absolute_price_schedule=discharging_absolute_price_schedule,
        )

        schedule_tuple = ScheduleTuple(
            schedule_tuple_id=1,
            charging_schedule=charging_schedule,
            discharging_schedule=discharging_schedule,
        )

        scheduled_params = ScheduledScheduleExchangeResParams(
            schedule_tuples=[schedule_tuple]
        )

        return scheduled_params

    def get_dynamic_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Optional[DynamicScheduleExchangeResParams]:
        """Overrides EVSEControllerInterface.get_dynamic_se_params()."""
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Dynamic parameters for ScheduleExchangeRes not yet ready")
            return None

        price_level_schedule_entry = PriceLevelScheduleEntry(
            duration=3600, price_level=1
        )

        schedule_entries = PriceLevelScheduleEntryList(
            entries=[price_level_schedule_entry]
        )

        price_level_schedule = PriceLevelSchedule(
            id="id1",
            time_anchor=0,
            schedule_id=1,
            schedule_description="What a great description",
            num_price_levels=1,
            schedule_entries=schedule_entries,
        )

        dynamic_params = DynamicScheduleExchangeResParams(
            departure_time=7200,
            min_soc=30,
            target_soc=80,
            price_level_schedule=price_level_schedule,
        )

        return dynamic_params

    def get_energy_service_list(self) -> ServiceList:
        """Overrides EVSEControllerInterface.get_energy_service_list()."""
        # AC = 1, DC = 2, AC_BPT = 5, DC_BPT = 6
        service_ids = [2]
        service_list: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            service_list.services.append(
                Service(service_id=service_id, free_service=False)
            )

        return service_list

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
    ) -> Optional[List[SAScheduleTuple]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTuple] = []

        # PMaxSchedule
        p_max = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
        p_max_schedule_entry = PMaxScheduleEntry(
            p_max=p_max, time_interval=RelativeTimeInterval(start=0, duration=3600)
        )
        p_max_schedule = PMaxSchedule(schedule_entries=[p_max_schedule_entry])

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
        sa_schedule_tuple = SAScheduleTuple(
            tuple_id=1,
            p_max_schedule=p_max_schedule,
            sales_tariff=sales_tariff,
        )

        # TODO We could also implement an optional SalesTariff, but for the sake of
        #      time we'll do that later (after the basics are implemented).
        #      When implementing the SalesTariff, we also need to apply a digital
        #      signature to it.
        sa_schedule_list.append(sa_schedule_tuple)

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

    def service_renegotiation_supported(self) -> bool:
        """Overrides EVSEControllerInterface.service_renegotiation_supported()."""
        return False

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

    def get_service_parameter_list(self, service_id: int) -> ServiceParameterList:
        """Overrides EVSEControllerInterface.get_service_parameter_list()."""
        if service_id == ServiceV20.DC.service_id:
            service_parameter_list = ServiceParameterList(
                parameter_sets=[
                    ParameterSet(
                        id=1,
                        parameters=[
                            Parameter(
                                name=ParameterName.CONNECTOR,
                                int_value=DCConnector.EXTENDED,
                            ),
                            Parameter(
                                name=ParameterName.CONTROL_MODE,
                                int_value=ControlMode.DYNAMIC,
                            ),
                            Parameter(
                                name=ParameterName.MOBILITY_NEEDS_MODE,
                                int_value=MobilityNeedsMode.EVCC_ONLY,
                            ),
                            Parameter(
                                name=ParameterName.PRICING, int_value=Pricing.NONE
                            ),
                        ],
                    )
                ]
            )

            return service_parameter_list
        else:
            logger.error(
                f"Unknown service ID {service_id}, can't provide ServiceParameterList"
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

    def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        return PVEVSEMaxVoltageLimit(multiplier=0, value=600, unit="V")

    def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        return PVEVSEMaxCurrentLimit(multiplier=0, value=300, unit="A")

    def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        return PVEVSEMaxPowerLimit(multiplier=1, value=1000, unit="W")
