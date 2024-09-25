"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import base64
import logging
import math
import time
import calendar
from typing import Dict, List, Optional, Union, cast
import dateutil.parser
import os

from iso15118.secc.controller.common import UnknownEnergyService
from iso15118.secc.controller.evse_data import (
    EVSEACCLLimits,
    EVSEACCPDLimits,
    EVSEDataContext,
    EVSEDCCLLimits,
    EVSEDCCPDLimits,
    EVSERatedLimits,
    EVSESessionLimits,
)
from iso15118.secc.controller.interface import (
    AuthorizationResponse,
    EVDataContext,
    EVSEControllerInterface,
    ServiceStatus,
)
from iso15118.shared.exceptions import EncryptionError, PrivateKeyReadError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    PVEVSEEnergyToBeDelivered,
)
from iso15118.shared.messages.datatypes import EVSENotification as EVSENotificationV2
from iso15118.shared.messages.datatypes import (
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
    PVEVSECurrentRegulationTolerance
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
    ResponseCode as ResponseCodeDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from iso15118.shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Namespace,
    PriceAlgorithm,
    Protocol,
    ServiceV20,
    SessionStopAction,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_2.body import (
    Body,
    CertificateInstallationReq,
    CertificateInstallationRes,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    EMAID,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    CertificateChain,
    DHPublicKey,
    EncryptedPrivateKey,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PMaxSchedule,
    PMaxScheduleEntry,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    RelativeTimeInterval,
)
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
    SubCertificates,
)
from iso15118.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AbsolutePriceSchedule,
    AdditionalService,
    AdditionalServiceList,
    ChargingSchedule,
    DynamicScheduleExchangeResParams,
    OverstayRule,
    OverstayRuleList,
    Parameter,
    ParameterSet,
    PowerSchedule,
    PowerScheduleEntry,
    PowerScheduleEntryList,
    PriceLevelSchedule,
    PriceLevelScheduleEntry,
    PriceLevelScheduleEntryList,
    PriceRule,
    PriceRuleStack,
    PriceRuleStackList,
    ProviderID,
    ScheduledScheduleExchangeResParams,
    ScheduleExchangeReq,
    ScheduleTuple,
    SelectedEnergyService,
    Service,
    ServiceList,
    ServiceParameterList,
    TaxRule,
    TaxRuleList,
)
from iso15118.shared.messages.iso15118_20.common_types import EVSEStatus
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryResParams,
    DCChargeParameterDiscoveryResParams,
)
from iso15118.shared.security import (
    CertPath,
    KeyEncoding,
    KeyPasswordPath,
    KeyPath,
    create_signature,
    encrypt_priv_key,
    get_cert_cn,
    load_cert,
    load_priv_key,
)
from iso15118.shared.settings import V20_EVSE_SERVICES_CONFIG, get_PKI_PATH

from iso15118.secc.everest import context as EVEREST_CONTEXT, float2Value_Multiplier
from iso15118.secc.everest import float2Value_Multiplier

import asyncio
from iso15118.shared.states import State

logger = logging.getLogger(__name__)

EVEREST_CHARGER_STATE = EVEREST_CONTEXT.charger_state

def get_evse_context():
    ac_limits = EVSEACCPDLimits(
        max_current=10,
        max_charge_power=10,
        min_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        min_charge_power_l2=10,
        min_charge_power_l3=10,
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        min_discharge_power_l2=10,
        min_discharge_power_l3=10,
    )
    dc_limits = EVSEDCCPDLimits(
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        min_charge_current=10,
        max_voltage=10,
        min_voltage=10,
        # 15118-20 DC BPT
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_discharge_current=10,
    )
    ac_cl_limits = EVSEACCLLimits(
        max_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        max_charge_reactive_power=10,
        max_charge_reactive_power_l2=10,
        max_charge_reactive_power_l3=10,
        # BPT attributes
        max_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        max_discharge_reactive_power=10,
        max_discharge_active_power_l2=10,
        max_discharge_active_power_l3=10,
    )
    dc_cl_limits = EVSEDCCLLimits(
        # Optional in 15118-20 DC CL (Scheduled)
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        max_voltage=10,
        # Optional and present in 15118-20 DC BPT CL (Scheduled)
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_voltage=10,
    )
    rated_limits: EVSERatedLimits = EVSERatedLimits(
        ac_limits=ac_limits,
        dc_limits=dc_limits,
    )

    session_limits: EVSESessionLimits = EVSESessionLimits(
        ac_limits=ac_cl_limits,
        dc_limits=dc_cl_limits,
    )
    evse_data_context = EVSEDataContext(
        rated_limits=rated_limits, session_limits=session_limits
    )
    evse_data_context.nominal_voltage = 10
    evse_data_context.nominal_frequency = 10
    evse_data_context.max_power_asymmetry = 10
    evse_data_context.power_ramp_limit = 10
    evse_data_context.present_active_power = 10
    evse_data_context.present_active_power_l2 = 10
    evse_data_context.present_active_power_l3 = 10
    evse_data_context.current_regulation_tolerance = 10
    evse_data_context.energy_to_be_delivered = 10
    evse_data_context.present_current = 1
    evse_data_context.present_voltage = 1
    return evse_data_context


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    def __init__(self):
        super().__init__()
        self.evseIsolationMonitoringActive = False
        self.ev_data_context = EVDataContext()
        self.evse_data_context = get_evse_context()

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================
    async def set_status(self, status: ServiceStatus) -> None:
        logger.debug(f"New Status: {status}")

    async def get_evse_id(self, protocol: Protocol) -> str:
        """Overrides EVSEControllerInterface.get_evse_id()."""

        if protocol == Protocol.DIN_SPEC_70121:
            #  To transform a string-based DIN SPEC 91286 EVSE ID to hexBinary
            #  representation and vice versa, the following conversion rules shall
            #  be used for each character and hex digit: '0' <--> 0x0, '1' <--> 0x1,
            #  '2' <--> 0x2, '3' <--> 0x3, '4' <--> 0x4, '5' <--> 0x5, '6' <--> 0x6,
            #  '7' <--> 0x7, '8' <--> 0x8, '9' <--> 0x9, '*' <--> 0xA,
            #  Unused <--> 0xB .. 0xF.
            # Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
            # as “0x49 0xA8 0x9A 0x63 0x60”.
            evse_id_din: str = EVEREST_CHARGER_STATE.EVSEID_DIN
            return evse_id_din
        else:
            evse_id: str = EVEREST_CHARGER_STATE.EVSEID
            return evse_id

    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""

        supported_energy_transfer_modes: List[EnergyTransferModeEnum] = []
        for modes in EVEREST_CHARGER_STATE.SupportedEnergyTransferMode:
            energy_mode = EnergyTransferModeEnum(modes)
            if protocol == Protocol.DIN_SPEC_70121:
                if energy_mode is EnergyTransferModeEnum.DC_CORE or energy_mode is EnergyTransferModeEnum.DC_EXTENDED:
                    supported_energy_transfer_modes.append(energy_mode)
            else:
                supported_energy_transfer_modes.append(energy_mode)

        return supported_energy_transfer_modes

    async def get_schedule_exchange_params(
        self,
        selected_energy_service: SelectedEnergyService,
        control_mode: ControlMode,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Union[ScheduledScheduleExchangeResParams, DynamicScheduleExchangeResParams]:
        if control_mode == ControlMode.SCHEDULED:
            return await self.get_scheduled_se_params(
                selected_energy_service, schedule_exchange_req
            )
        else:
            return await self.get_dynamic_se_params(
                selected_energy_service, schedule_exchange_req
            )

    async def get_scheduled_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> ScheduledScheduleExchangeResParams:
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
            schedule_entry_list=PowerScheduleEntryList(
                entries=[charging_power_schedule_entry]
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
            renewable_energy_percentage=0,
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        price_rule_stack = PriceRuleStack(
            duration=3600, price_rules=[price_rule])

        price_rule_stacks = PriceRuleStackList(
            price_rule_stacks=[price_rule_stack])

        overstay_rule = OverstayRule(
            description="What a great description",
            start_time=0,
            fee=RationalNumber(exponent=0, value=50),
            fee_period=3600,
        )

        overstay_rules = OverstayRuleList(
            time_threshold=3600,
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
            time_anchor=0,
            schedule_id=1,
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

        discharging_power_schedule_entry = PowerScheduleEntry(
            duration=3600,
            power=RationalNumber(exponent=3, value=10)
            # Check if AC ThreePhase applies (Connector parameter within parameter set
            # of SelectedEnergyService) if you want to add power_l2 and power_l3 values
        )

        discharging_power_schedule = PowerSchedule(
            time_anchor=0,
            schedule_entry_list=PowerScheduleEntryList(
                entries=[discharging_power_schedule_entry]
            ),
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

    async def get_service_parameter_list(
        self, service_id: int
    ) -> Optional[ServiceParameterList]:
        """Overrides EVSEControllerInterface.get_service_parameter_list()."""
        parameter_sets_list: List[ParameterSet] = []

        try:
            connector_parameter = Parameter(name="Connector", int_value=2)

            nominal_voltage = 400

            nominal_voltage_parameter = Parameter(
                name="EVSENominalVoltage", int_value=nominal_voltage
            )
            # TODO: map the pricing type
            pricing_parameter = Parameter(name="Pricing", int_value=0)

            parameter_set_id: int = 1
            # According to the spec, both EVSE and EV must offer Scheduled = 1 and
            # Dynamic = 2 control modes
            # As the EVCC Simulator will choose the first parameter set by default,
            # we first advertise the one with Dynamic control mode 2
            # The env variable 15118_20_PRIORITIZE_DYNAMIC_CONTROL_MODE is provided
            # if this is to be inverted. When set, the first parameter set will be for
            # scheduled control mode. This will be removed soon. For testing purposes
            # only.
            control_modes = [1, 2]

            for control_mode in control_modes:
                control_mode_parameter = Parameter(
                    name="ControlMode", int_value=control_mode
                )
                mobility_needs_parameter = Parameter(
                    name="MobilityNeedsMode", int_value=control_mode
                )
                parameters_list: list = [
                    connector_parameter,
                    nominal_voltage_parameter,
                    pricing_parameter,
                    control_mode_parameter,
                    mobility_needs_parameter,
                ]
                parameter_set = ParameterSet(
                    id=parameter_set_id, parameters=parameters_list
                )
                parameter_sets_list.append(parameter_set)
                # increment the parameter set id for the next set of them
                parameter_set_id += 1
                if control_mode == 2:
                    # [V2G20-2663]:The SECC shall only offer MobilityNeedsMode equal
                    # to ‘2’ when ControlMode is set to ‘2’ (Dynamic).
                    # So, for Dynamic mode the MobilityNeeds can have the value
                    # of 1 or 2 so in this if clause we insert another parameter set
                    # for Dynamic mode but for MobilityNeedsMode = 1 (MobilityNeeds
                    # provided by the EVCC).
                    parameters_list.remove(mobility_needs_parameter)
                    mobility_needs_parameter = Parameter(
                        name="MobilityNeedsMode", int_value=1
                    )
                    parameters_list.append(mobility_needs_parameter)
                    parameter_set = ParameterSet(
                        id=parameter_set_id, parameters=parameters_list
                    )
                    parameter_sets_list.append(parameter_set)
                    # increment the parameter set id for the next set
                    parameter_set_id += 1
        except AttributeError as e:
            logger.error(
                f"No ServiceParameterList available for service ID {
                    service_id}"
            )
            raise e

        return ServiceParameterList(parameter_sets=parameter_sets_list)

    async def get_dynamic_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> DynamicScheduleExchangeResParams:
        """Overrides EVSEControllerInterface.get_dynamic_se_params()."""
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

    async def get_energy_service_list(self) -> ServiceList:
        """Overrides EVSEControllerInterface.get_energy_service_list()."""
        # AC = 1, DC = 2, AC_BPT = 5, DC_BPT = 6;
        # DC_ACDP = 4 and DC_ADCP_BPT NOT supported

        current_protocol = self.get_selected_protocol()
        if current_protocol == Protocol.ISO_15118_20_DC:
            service_ids = [2, 6]
        elif current_protocol == Protocol.ISO_15118_20_AC:
            service_ids = [1, 5]

        service_list: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            service_list.services.append(
                Service(service_id=service_id, free_service=False)
            )

        return service_list

    def is_eim_authorized(self) -> bool:
        """Overrides EVSEControllerInterface.is_eim_authorized()."""
        return False

    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationResponse:
        """Overrides EVSEControllerInterface.is_authorized()."""

        if id_token_type is AuthorizationTokenType.EXTERNAL:

            if EVEREST_CHARGER_STATE.auth_status == "Accepted":
                return AuthorizationStatus.ACCEPTED

        elif id_token_type is AuthorizationTokenType.EMAID:

            pnc_auth_status: str = EVEREST_CHARGER_STATE.auth_status
            certificate_status = EVEREST_CHARGER_STATE.certificate_status

            if pnc_auth_status == "Accepted" and certificate_status in ['Ongoing', 'Accepted']:
                return AuthorizationStatus.ACCEPTED
            elif (pnc_auth_status == "Ongoing" and certificate_status == "Ongoing"):
                return AuthorizationStatus.ONGOING
            else:
                return AuthorizationStatus.REJECTED

    async def get_sa_schedule_list_dinspec(
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

    async def get_sa_schedule_list(
        self,
        ev_data_context: EVDataContext,
        is_free_charging_service: bool,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTuple] = []

        if departure_time == 0:
            # [V2G2-304] If no departure_time is provided, the sum of the individual
            # time intervals shall be greater than or equal to 24 hours.
            departure_time = 86400

        # PMaxSchedule entries
        schedule_entries = []
        # SalesTariff
        sales_tariff_entries: List[SalesTariffEntry] = []
        remaining_charge_duration = departure_time
        counter = 1
        start = 0
        current_pmax_val = 7000
        while remaining_charge_duration > 0:
            if current_pmax_val == 7000:
                p_max = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
                current_pmax_val = 11000
            else:
                p_max = PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT)
                current_pmax_val = 7000

            p_max_schedule_entry = PMaxScheduleEntry(
                p_max=p_max, time_interval=RelativeTimeInterval(start=start)
            )

            sales_tariff_entry = SalesTariffEntry(
                e_price_level=counter,
                time_interval=RelativeTimeInterval(start=start),
            )

            if remaining_charge_duration <= 86400:
                p_max_schedule_entry = PMaxScheduleEntry(
                    p_max=p_max,
                    time_interval=RelativeTimeInterval(
                        start=start, duration=remaining_charge_duration
                    ),
                )

                sales_tariff_entry = SalesTariffEntry(
                    e_price_level=counter,
                    time_interval=RelativeTimeInterval(
                        start=start, duration=remaining_charge_duration
                    ),
                )

            remaining_charge_duration -= 86400
            start += 86400
            counter += 1
            schedule_entries.append(p_max_schedule_entry)
            sales_tariff_entries.append(sales_tariff_entry)

        p_max_schedule = PMaxSchedule(schedule_entries=schedule_entries)

        sales_tariff = SalesTariff(
            id="id1",
            sales_tariff_id=10,  # a random id
            sales_tariff_entry=sales_tariff_entries,
            num_e_price_levels=len(sales_tariff_entries),
        )

        # Putting the list of SAScheduleTuple entries together
        sa_schedule_tuple = SAScheduleTuple(
            sa_schedule_tuple_id=1,
            p_max_schedule=p_max_schedule,
            sales_tariff=None if is_free_charging_service else sales_tariff,
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

    async def get_meter_info_v2(self) -> MeterInfoV2:
        """Overrides EVSEControllerInterface.get_meter_info_v2()."""
        meter_id: str = "EVerest"

        powermeter: dict = EVEREST_CHARGER_STATE.powermeter
        meter_reading: int = int(powermeter["energy_Wh_import"]["total"])
        t_meter_datetime = dateutil.parser.isoparse(powermeter["timestamp"])
        if powermeter["meter_id"]:
            meter_id = str(powermeter["meter_id"])

        return MeterInfoV2(
            meter_id=meter_id, t_meter=int(calendar.timegm(t_meter_datetime.timetuple())), meter_reading=meter_reading
        )

    async def get_meter_info_v20(self) -> MeterInfoV20:
        """Overrides EVSEControllerInterface.get_meter_info_v20()."""
        return MeterInfoV20(
            meter_id="Switch-Meter-123",
            charged_energy_reading_wh=10,
            meter_timestamp=time.time(),
        )

    async def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """Overrides EVSEControllerInterface.get_supported_providers()."""
        return None

    async def set_hlc_charging(self, is_ongoing: bool) -> None:
        """Overrides EVSEControllerInterface.set_hlc_charging()."""
        pass

    async def stop_charger(self) -> None:
        pass

    async def get_cp_state(self) -> CpState:
        """Overrides EVSEControllerInterface.set_cp_state()."""
        return CpState.C2

    async def service_renegotiation_supported(self) -> bool:
        """Overrides EVSEControllerInterface.service_renegotiation_supported()."""
        return False

    async def is_contactor_closed(self) -> bool:
        """Overrides EVSEControllerInterface.is_contactor_closed()."""
        startTime_ns: int = time.time_ns()
        timeout: int = 0
        PERFORMANCE_TIMEOUT: int = 4500

        while timeout < PERFORMANCE_TIMEOUT:
            if EVEREST_CHARGER_STATE.contactorClosed is True:
                return True

            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        return False

    async def is_contactor_opened(self) -> bool:
        """Overrides EVSEControllerInterface.is_contactor_opened()."""
        startTime_ns: int = time.time_ns()
        timeout: int = 0
        PERFORMANCE_TIMEOUT: int = 4500

        while timeout < PERFORMANCE_TIMEOUT:
            if EVEREST_CHARGER_STATE.contactorOpen is True:
                return True

            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        return False

    async def get_evse_status(self) -> Optional[EVSEStatus]:
        """Overrides EVSEControllerInterface.get_evse_status()."""
        # TODO: this function can be generic to all protocols.
        #       We can make use of the method `get_evse_id`
        #       or other way to get the evse_id to request
        #       status of a specific evse_id. We can also use the
        #       `self.comm_session.protocol` obtained during SAP,
        #       and inject its value into the `get_evse_status`
        #       to decide on providing the -2ß EVSEStatus or the
        #       -2 AC or DC one and the `selected_charging_type_is_ac` in -2
        #       to decide on returning the ACEVSEStatus or the DCEVSEStatus
        #
        # Just as an example, here is how the return could look like
        # from iso15118.shared.messages.iso15118_20.common_types import (
        #    EVSENotification as EVSENotificationV20,
        # )
        # return EVSEStatus(
        #        notification_max_delay=0,
        #        evse_notification=EVSENotificationV20.TERMINATE
        #    )
        return None

    async def get_receipt_required(self) -> bool:
        return EVEREST_CHARGER_STATE.ReceiptRequired

    async def reset_evse_values(self):
        EVEREST_CHARGER_STATE.reset()

    async def get_evse_payment_options(self) -> list:
        return EVEREST_CHARGER_STATE.PaymentOptions

    async def is_free(self) -> bool:
        return EVEREST_CHARGER_STATE.FreeService

    async def set_present_protocol_state(self, state: State):
        logger.info(f"iso15118 state: {str(state)}")

    async def allow_cert_install_service(self) -> bool:
        return EVEREST_CHARGER_STATE.certificate_service_supported

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""

        notification: EVSENotificationV2 = EVSENotificationV2.NONE
        if EVEREST_CHARGER_STATE.stop_charging is True:
            notification = EVSENotificationV2.STOP_CHARGING

        return ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=notification,
            rcd=EVEREST_CHARGER_STATE.RCD_Error,
        )

    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""

        nominal_voltage_value, nominal_voltage_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSENominalVoltage)
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=nominal_voltage_multiplier, value=nominal_voltage_value, unit=UnitSymbol.VOLTAGE
        )
        max_current_value, max_current_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaxCurrent)
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=await self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    async def get_ac_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Optional[
        Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ]
    ]:
        """Overrides EVSEControllerInterface.get_ac_charge_params_v20()."""
        ac_charge_parameter_discovery_res_params = ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(30000),
            evse_max_charge_power_l2=RationalNumber.get_rational_repr(30000),
            evse_max_charge_power_l3=RationalNumber.get_rational_repr(30000),
            evse_min_charge_power=RationalNumber.get_rational_repr(100),
            evse_min_charge_power_l2=RationalNumber.get_rational_repr(100),
            evse_min_charge_power_l3=RationalNumber.get_rational_repr(100),
            evse_nominal_frequency=RationalNumber.get_rational_repr(50),
            max_power_asymmetry=RationalNumber.get_rational_repr(0),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(100),
            evse_present_active_power=RationalNumber.get_rational_repr(0),
            evse_present_active_power_l2=RationalNumber.get_rational_repr(0),
            evse_present_active_power_l3=RationalNumber.get_rational_repr(0),
        )
        if energy_service == ServiceV20.AC:
            return ac_charge_parameter_discovery_res_params
        elif energy_service == ServiceV20.AC_BPT:
            return BPTACChargeParameterDiscoveryResParams(
                **(ac_charge_parameter_discovery_res_params.dict()),
                evse_max_discharge_power=RationalNumber(
                    exponent=0, value=3000),
                evse_max_discharge_power_l2=RationalNumber(
                    exponent=0, value=3000),
                evse_max_discharge_power_l3=RationalNumber(
                    exponent=0, value=3000),
                evse_min_discharge_power=RationalNumber(exponent=0, value=300),
                evse_min_discharge_power_l2=RationalNumber(
                    exponent=0, value=300),
                evse_min_discharge_power_l3=RationalNumber(
                    exponent=0, value=300),
            )
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")

    async def get_ac_evse_max_current(self) -> PVEVSEMaxCurrent:
        max_current_value, max_current_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaxCurrent)
        return PVEVSEMaxCurrent(multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE)

    async def get_ac_evse_max_current(self) -> PVEVSEMaxCurrent:
        max_current_value, max_current_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaxCurrent)
        return PVEVSEMaxCurrent(multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE)

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""

        notification: EVSENotificationV2 = EVSENotificationV2.NONE
        if EVEREST_CHARGER_STATE.stop_charging is True:
            notification = EVSENotificationV2.STOP_CHARGING

        evse_isolation: IsolationLevel = IsolationLevel(
            EVEREST_CHARGER_STATE.EVSEIsolationStatus)

        evse_status_code: DCEVSEStatusCode = DCEVSEStatusCode.EVSE_READY
        if EVEREST_CHARGER_STATE.EVSE_UtilityInterruptEvent is True:
            evse_status_code = DCEVSEStatusCode.EVSE_UTILITY_INTERUPT_EVENT
        elif EVEREST_CHARGER_STATE.EVSE_Malfunction is True:
            evse_status_code = DCEVSEStatusCode.EVSE_MALFUNCTION
        elif EVEREST_CHARGER_STATE.EVSE_EmergencyShutdown is True:
            evse_status_code = DCEVSEStatusCode.EVSE_EMERGENCY_SHUTDOWN
        elif self.evseIsolationMonitoringActive is True:
            evse_status_code = DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
        elif EVEREST_CHARGER_STATE.stop_charging is True:
            evse_status_code = DCEVSEStatusCode.EVSE_SHUTDOWN

        return DCEVSEStatus(
            evse_notification=notification,
            notification_max_delay=0,
            evse_isolation_status=evse_isolation,
            evse_status_code=evse_status_code,
        )

    async def get_dc_charge_parameters(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""

        c_ripple_value, c_ripple_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEPeakCurrentRipple
        )
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumCurrentLimit
        )
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumPowerLimit
        )
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumVoltageLimit
        )
        c_min_limit_value, c_min_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMinimumCurrentLimit
        )
        v_min_limit_value, v_min_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMinimumVoltageLimit
        )

        dcEVSEChargeParameter: DCEVSEChargeParameter = DCEVSEChargeParameter(
            dc_evse_status=await self.get_dc_evse_status(),
            evse_maximum_power_limit=PVEVSEMaxPowerLimit(
                multiplier=p_max_limit_multiplier, value=p_max_limit_value, unit="W"
            ),
            evse_maximum_current_limit=PVEVSEMaxCurrentLimit(
                multiplier=c_max_limit_multiplier, value=c_max_limit_value, unit="A"
            ),
            evse_maximum_voltage_limit=PVEVSEMaxVoltageLimit(
                multiplier=v_max_limit_multiplier, value=v_max_limit_value, unit="V"
            ),
            evse_minimum_current_limit=PVEVSEMinCurrentLimit(
                multiplier=c_min_limit_multiplier, value=c_min_limit_value, unit="A"
            ),
            evse_minimum_voltage_limit=PVEVSEMinVoltageLimit(
                multiplier=v_min_limit_multiplier, value=v_min_limit_value, unit="V"
            ),
            evse_peak_current_ripple=PVEVSEPeakCurrentRipple(
                multiplier=c_ripple_multiplier, value=c_ripple_value, unit="A"
            )
        )

        if EVEREST_CHARGER_STATE.EVSECurrentRegulationTolerance is not None:
            current_reg_tol_value, current_reg_tol_multiplier = float2Value_Multiplier(
                EVEREST_CHARGER_STATE.EVSECurrentRegulationTolerance
            )
            dcEVSEChargeParameter.evse_current_regulation_tolerance = PVEVSECurrentRegulationTolerance(
                multiplier=current_reg_tol_multiplier, value=current_reg_tol_value, unit="A"
            )
        if EVEREST_CHARGER_STATE.EVSEEnergyToBeDelivered is not None:
            energy_deliver_value, energy_deliver_multiplier = float2Value_Multiplier(
                EVEREST_CHARGER_STATE.EVSEEnergyToBeDelivered
            )
            dcEVSEChargeParameter.evse_energy_to_be_delivered = PVEVSEEnergyToBeDelivered(
                multiplier=energy_deliver_multiplier, value=energy_deliver_value, unit="Wh"
            )

        return dcEVSEChargeParameter

    async def get_evse_present_voltage(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentVoltage, RationalNumber]:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        v_value, v_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEPresentVoltage)
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            return PVEVSEPresentVoltage(multiplier=v_multiplier, value=v_value, unit="V")
        else:
            return RationalNumber(exponent=v_multiplier, value=v_value)

    async def get_evse_present_current(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentCurrent, RationalNumber]:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        c_value, c_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEPresentCurrent)
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            return PVEVSEPresentCurrent(multiplier=c_multiplier, value=c_value, unit="A")
        else:
            return RationalNumber(exponent=c_multiplier, value=c_value)

    async def start_cable_check(self):
        """Overrides EVSEControllerInterface.start_cable_check()."""
        pass

    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """Overrides EVSEControllerInterface.get_cable_check_status()."""
        return IsolationLevel.VALID

    async def send_charging_command(
        self,
        ev_target_voltage: Optional[float],
        ev_target_current: Optional[float],
        is_precharge: bool = False,
        is_session_bpt: bool = False,
    ):
        pass

    async def is_evse_current_limit_achieved(self) -> bool:
        if EVEREST_CHARGER_STATE.EVSEPresentCurrent >= EVEREST_CHARGER_STATE.EVSEMaximumCurrentLimit:
            return True
        return False

    async def is_evse_voltage_limit_achieved(self) -> bool:
        if EVEREST_CHARGER_STATE.EVSEPresentVoltage >= EVEREST_CHARGER_STATE.EVSEMaximumVoltageLimit:
            return True
        return False

    async def is_evse_power_limit_achieved(self) -> bool:
        presentPower: float = EVEREST_CHARGER_STATE.EVSEPresentCurrent * \
            EVEREST_CHARGER_STATE.EVSEPresentVoltage
        if presentPower >= EVEREST_CHARGER_STATE.EVSEMaximumPowerLimit:
            return True
        return False

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumVoltageLimit
        )
        return PVEVSEMaxVoltageLimit(multiplier=v_max_limit_multiplier, value=v_max_limit_value, unit="V")

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumCurrentLimit
        )
        return PVEVSEMaxCurrentLimit(multiplier=c_max_limit_multiplier, value=c_max_limit_value, unit="A")

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
            EVEREST_CHARGER_STATE.EVSEMaximumPowerLimit
        )
        return PVEVSEMaxPowerLimit(multiplier=p_max_limit_multiplier, value=p_max_limit_value, unit="W")

    async def get_dc_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Union[
        DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
    ]:
        """Override EVSEControllerInterface.get_dc_charge_params_v20()."""
        dc_charge_parameter_discovery_res = DCChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(1000),
            evse_min_charge_power=RationalNumber.get_rational_repr(100),
            evse_max_charge_current=RationalNumber.get_rational_repr(100),
            evse_min_charge_current=RationalNumber.get_rational_repr(10),
            evse_max_voltage=RationalNumber.get_rational_repr(500),
            evse_min_voltage=RationalNumber.get_rational_repr(10),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(10),
        )
        if energy_service == ServiceV20.DC:
            return dc_charge_parameter_discovery_res
        elif energy_service == ServiceV20.DC_BPT:
            return BPTDCChargeParameterDiscoveryResParams(
                **(dc_charge_parameter_discovery_res.dict()),
                evse_max_discharge_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.dc_bpt_limits.evse_max_discharge_power  # noqa
                ),
                evse_min_discharge_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.dc_bpt_limits.evse_min_discharge_power  # noqa
                ),
                evse_max_discharge_current=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.dc_bpt_limits.evse_max_discharge_current  # noqa
                ),
                evse_min_discharge_current=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.dc_bpt_limits.evse_min_discharge_current  # noqa
                ),
            )
        return None

    async def get_dc_charge_loop_params_v20(
        self, control_mode: ControlMode, selected_service: ServiceV20
    ) -> Optional[
        Union[
            ScheduledDCChargeLoopResParams,
            BPTScheduledDCChargeLoopResParams,
            DynamicDCChargeLoopRes,
            BPTDynamicDCChargeLoopRes,
        ]
    ]:
        """Overrides EVSEControllerInterface.get_dc_charge_loop_params()."""
        if selected_service == ServiceV20.DC:
            if control_mode == ControlMode.SCHEDULED:
                scheduled_params = ScheduledDCChargeLoopResParams(
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_power  # noqa
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_charge_power  # noqa
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_current  # noqa
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_voltage  # noqa
                    ),
                )
                return scheduled_params
            elif control_mode == ControlMode.DYNAMIC:
                dynamic_params = DynamicDCChargeLoopRes(
                    departure_time=self.evse_data_context.session_context.ev_departure_time,  # noqa
                    min_soc=self.evse_data_context.session_context.ev_min_soc,
                    target_soc=self.evse_data_context.session_context.ev_target_soc,
                    ack_max_delay=self.evse_data_context.session_context.ack_max_delay,
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_power  # noqa
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_charge_power  # noqa
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_current  # noqa
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_voltage  # noqa
                    ),
                )
                return dynamic_params
            return None
        elif selected_service == ServiceV20.DC_BPT:
            if control_mode == ControlMode.SCHEDULED:
                bpt_scheduled_params = BPTScheduledDCChargeLoopResParams(
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_power  # noqa
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_charge_power  # noqa
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_current  # noqa
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_voltage  # noqa
                    ),
                    evse_max_discharge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_discharge_power  # noqa
                    ),
                    evse_min_discharge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_discharge_power  # noqa
                    ),
                    evse_max_discharge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_discharge_current  # noqa
                    ),
                    evse_min_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_voltage  # noqa
                    ),
                )
                return bpt_scheduled_params
            else:
                bpt_dynamic_params = BPTDynamicDCChargeLoopRes(
                    departure_time=self.evse_data_context.session_context.ev_departure_time,  # noqa
                    min_soc=self.evse_data_context.session_context.ev_min_soc,
                    target_soc=self.evse_data_context.session_context.ev_target_soc,
                    ack_max_delay=self.evse_data_context.session_context.ack_max_delay,
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_power  # noqa
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_charge_power  # noqa
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_charge_current  # noqa
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_voltage  # noqa
                    ),
                    evse_max_discharge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_discharge_power  # noqa
                    ),
                    evse_min_discharge_power=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_discharge_power  # noqa
                    ),
                    evse_max_discharge_current=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_max_discharge_current  # noqa
                    ),
                    evse_min_voltage=RationalNumber.get_rational_repr(
                        self.evse_data_context.session_context.dc_limits.evse_min_voltage  # noqa
                    ),
                )
                return bpt_dynamic_params
        else:
            logger.error(f"Energy service {
                         selected_service.name} not yet supported")
            return None

    async def setIsolationMonitoringActive(self, value: bool):
        self.evseIsolationMonitoringActive = value

    async def isCableCheckFinished(self) -> bool:
        return EVEREST_CHARGER_STATE.cableCheck_Finished

    async def get_15118_ev_certificate(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:
        """
        Overrides EVSEControllerInterface.get_15118_ev_certificate().

        # Here we simply mock the actions of the backend.
        # The code here is almost the same as what is done if USE_CPO_BACKEND
        # is set to False. Except that both the request and response is base64 encoded.
        """

        startTime_ns: int = time.time_ns()
        timeout: int = 0
        PERFORMANCE_TIMEOUT: int = 4500

        while timeout < PERFORMANCE_TIMEOUT:

            Response: dict = EVEREST_CHARGER_STATE.existream_status
            if Response:
                if Response["certificateAction"] == "Install":
                    if Response["status"] == "Accepted":
                        exiResponse: str = str(Response["exiResponse"])
                        return exiResponse
                    elif Response["status"] == "Failed":
                        raise Exception(
                            "The CSMS reported: Processing of the message was not successful")
                elif Response["certificateAction"] == "Update":
                    action: str = str(Response["certificateAction"])
                    raise Exception(
                        f"The wrong message was generated by the backend: {action}")

            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)

        raise Exception(
            "Timeout - The backend takes too long to generate the CertificateInstallationRes")

    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Overrides EVSEControllerInterface.update_data_link().
        """
        pass

    def ready_to_charge(self) -> bool:
        """
        Overrides EVSEControllerInterface.ready_to_charge().
        """
        return True

    async def session_ended(self, current_state: str, reason: str):
        """
        Reports the state and reason where the session ended.

        @param current_state: The current SDP/SAP/DIN/ISO15118-2/ISO15118-20 state.
        @param reason: Reason for ending the session.
        @param last_message: The last message that was either sent/received.
        """
        logger.info(f"Session ended in {current_state} ({reason}).")
