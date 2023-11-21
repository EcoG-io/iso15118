"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import base64
import logging
import time
from typing import Dict, List, Optional, Union, cast

from aiofile import async_open
from pydantic import BaseModel, Field

from iso15118.secc.controller.evse_data import (
    EVSEACBPTCPDLimits,
    EVSEACCLLimits,
    EVSEACCPDLimits,
    EVSEDataContext,
    EVSEDCBPTCPDLimits,
    EVSEDCCLLimits,
    EVSEDCCPDLimits,
    EVSERatedLimits,
    EVSESessionContext,
)
from iso15118.secc.controller.interface import (
    AuthorizationResponse,
    EVChargeParamsLimits,
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
)
from iso15118.shared.messages.datatypes import EVSENotification as EVSENotificationV2
from iso15118.shared.messages.datatypes import (
    PhysicalValue,
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
    BPTDynamicACChargeLoopResParams,
    BPTScheduledACChargeLoopResParams,
    DynamicACChargeLoopResParams,
    ScheduledACChargeLoopResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AbsolutePriceSchedule,
    AdditionalService,
    AdditionalServiceList,
    ChargingSchedule,
    DynamicScheduleExchangeResParams,
    OverstayRule,
    OverstayRuleList,
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
    BPTDynamicDCChargeLoopRes,
    BPTScheduledDCChargeLoopResParams,
    DCChargeParameterDiscoveryResParams,
    DynamicDCChargeLoopRes,
    ScheduledDCChargeLoopResParams,
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
from iso15118.shared.settings import SettingKey, shared_settings
from iso15118.shared.states import State

logger = logging.getLogger(__name__)


class V20ServiceParamMapping(BaseModel):
    service_id_parameter_set_mapping: Dict[int, ServiceParameterList] = Field(
        ..., alias="service_id_parameter_set_mapping"
    )


def get_evse_context():
    ac_limits = EVSEACCPDLimits(
        # 15118-2 AC CPD
        evse_nominal_voltage=10,
        evse_max_current=10,
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_power_l2=10,
        evse_max_charge_power_l3=10,
        evse_min_charge_power_l2=10,
        evse_min_charge_power_l3=10,
        evse_nominal_frequency=10,
        max_power_asymmetry=10,
        evse_power_ramp_limit=10,
        evse_present_active_power=10,
        evse_present_active_power_l2=10,
        evse_present_active_power_l3=10,
    )
    ac_bpt_limits = EVSEACBPTCPDLimits(
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_power_l2=10,
        evse_max_discharge_power_l3=10,
        evse_min_discharge_power_l2=10,
        evse_min_discharge_power_l3=10,
    )
    dc_limits = EVSEDCCPDLimits(
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_current=10,
        evse_min_charge_current=10,
        evse_max_voltage=10,
        evse_min_voltage=10,
        evse_power_ramp_limit=10,
        # 15118-2 DC, DINSPEC
        evse_current_regulation_tolerance=10,
        evse_peak_current_ripple=10,
        evse_energy_to_be_delivered=10,
    )
    dc_bpt_limits = EVSEDCBPTCPDLimits(
        # 15118-20 DC BPT
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_current=10,
        evse_min_discharge_current=10,
    )
    ac_cl_limits = EVSEACCLLimits(
        evse_target_active_power=10,
        evse_target_active_power_l2=10,
        evse_target_active_power_l3=10,
        evse_target_reactive_power=10,
        evse_target_reactive_power_l2=10,
        evse_target_reactive_power_l3=10,
        evse_present_active_power=10,
        evse_present_active_power_l2=10,
        evse_present_active_power_l3=10,
    )
    dc_cl_limits = EVSEDCCLLimits(
        # Optional in 15118-20 DC CL (Scheduled)
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_current=10,
        evse_max_voltage=10,
        # Optional and present in 15118-20 DC BPT CL (Scheduled)
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_current=10,
        evse_min_voltage=10,
    )
    rated_limits: EVSERatedLimits = EVSERatedLimits(
        ac_limits=ac_limits,
        ac_bpt_limits=ac_bpt_limits,
        dc_limits=dc_limits,
        dc_bpt_limits=dc_bpt_limits,
    )

    session_context: EVSESessionContext = EVSESessionContext(
        evse_present_voltage=1,
        evse_present_current=1,
        ac_limits=ac_cl_limits,
        dc_limits=dc_cl_limits,
    )

    return EVSEDataContext(rated_limits=rated_limits, session_context=session_context)


# This method is added to help read the service to parameter
# mapping (json format) from file. The key is in the dictionary is
# enum value of the energy transfer mode and value is the service parameter
async def read_service_id_parameter_mappings():
    try:
        async with async_open(
            shared_settings[SettingKey.V20_SERVICE_CONFIG], "r"
        ) as v20_service_config:
            try:
                json_mapping = await v20_service_config.read()
                v20_service_parameter_mapping = V20ServiceParamMapping.parse_raw(
                    json_mapping
                )
                return v20_service_parameter_mapping.service_id_parameter_set_mapping
            except ValueError as exc:
                raise ValueError(
                    f"Error reading 15118-20 service parameters settings file"
                    f" at {shared_settings[SettingKey.V20_SERVICE_CONFIG]}"
                ) from exc
    except (FileNotFoundError, IOError) as exc:
        raise FileNotFoundError(
            f"V20 config not found at {shared_settings[SettingKey.V20_SERVICE_CONFIG]}"
        ) from exc


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    v20_service_id_parameter_mapping: Optional[Dict[int, ServiceParameterList]] = None

    @classmethod
    async def create(cls):
        self = SimEVSEController()
        self.ev_data_context = EVDataContext()
        self.evse_data_context = get_evse_context()
        self.v20_service_id_parameter_mapping = (
            await read_service_id_parameter_mappings()
        )
        return self

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================
    async def set_status(self, status: ServiceStatus) -> None:
        logger.debug(f"New Status: {status}")

    async def get_evse_id(self, protocol: Protocol) -> str:
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

    async def get_supported_energy_transfer_modes(
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

        # It's not valid to have mixed energy transfer modes associated with
        # a single EVSE. Providing this here only for simulation purposes.
        # ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        dc_extended = EnergyTransferModeEnum.DC_EXTENDED
        return [dc_extended, ac_three_phase]

    async def get_scheduled_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Optional[ScheduledScheduleExchangeResParams]:
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

        price_rule_stack = PriceRuleStack(duration=3600, price_rules=[price_rule])

        price_rule_stacks = PriceRuleStackList(price_rule_stacks=[price_rule_stack])

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
        if self.v20_service_id_parameter_mapping is None:
            return None
        if service_id in self.v20_service_id_parameter_mapping.keys():
            service_parameter_list = self.v20_service_id_parameter_mapping[service_id]
        else:
            logger.error(
                f"No ServiceParameterList available for service ID {service_id}"
            )
            return None

        return service_parameter_list

    async def get_dynamic_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Optional[DynamicScheduleExchangeResParams]:
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
        protocol = self.get_selected_protocol()
        response_code: Optional[
            Union[ResponseCodeDINSPEC, ResponseCodeV2, ResponseCodeV20]
        ] = None
        if protocol == Protocol.DIN_SPEC_70121:
            response_code = ResponseCodeDINSPEC.OK
        elif protocol == Protocol.ISO_15118_20_COMMON_MESSAGES:
            response_code = ResponseCodeV20.OK
        else:
            response_code = ResponseCodeV2.OK

        return AuthorizationResponse(
            authorization_status=AuthorizationStatus.ACCEPTED,
            certificate_response_status=response_code,
        )

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
        ev_charge_params_limits: EVChargeParamsLimits,
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
        return MeterInfoV2(
            meter_id="Switch-Meter-123", meter_reading=12345, t_meter=time.time()
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
        return True

    async def is_contactor_opened(self) -> bool:
        """Overrides EVSEControllerInterface.is_contactor_opened()."""
        return True

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

    async def set_present_protocol_state(self, state: State):
        logger.info(f"iso15118 state: {str(state)}")

    async def send_charging_power_limits(
        self,
        protocol: Protocol,
        control_mode: ControlMode,
        selected_energy_service: ServiceV20,
    ) -> None:
        """
        This method shall merge the EV-EVSE charging power limits and send it

        Args:
            protocol: protocol selected (DIN, ISO 15118-2, ISO 15118-20_AC,..)
            control_mode: Control mode for this session - Scheduled/Dynamic
            selected_energy_service: Enum for this Service - AC/AC_BPT/DC/DC_BPT

        Returns: None

        """
        if protocol == Protocol.ISO_15118_20_AC:
            charge_parameters: Optional[
                Union[
                    ACChargeParameterDiscoveryResParams,
                    BPTACChargeParameterDiscoveryResParams,
                ]
            ]

            charge_parameters = await self.get_ac_charge_params_v20(
                selected_energy_service
            )

            ev_data_context = self.get_ev_data_context()
            logger.info(f"EV data context: {ev_data_context}")

            if isinstance(charge_parameters, BPTACChargeParameterDiscoveryResParams):
                max_discharge_power = (
                    ev_data_context.ev_session_context.dc_limits.ev_max_discharge_power
                )
                min_discharge_power = (
                    ev_data_context.ev_session_context.dc_limits.ev_min_discharge_power
                )

            max_charge_power = min(
                ev_data_context.ev_session_context.ac_limits.ev_max_charge_power,
                charge_parameters.evse_max_charge_power.get_decimal_value(),
            )

            min_charge_power = max(
                ev_data_context.ev_session_context.ac_limits.ev_min_charge_power,
                charge_parameters.evse_min_charge_power.get_decimal_value(),
            )

            logger.debug(
                f"\n\r --- EV-EVSE System Power Limits ---  \n"
                f"max_charge_power [W]: {max_charge_power}\n"
                f"min_charge_power [W]: {min_charge_power}\n"
                f"max_discharge_power [W]: {max_discharge_power}\n"
                f"min_discharge_power [W]: {min_discharge_power}\n"
            )
            # NOTE: Currently reactive limits are not available
            # https://iso15118.elaad.io/pt2/15118-20/user-group/-/issues/65
        return

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""
        return ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotificationV2.NONE,
            rcd=False,
        )

    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        )
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=0, value=32, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=await self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    async def get_ac_charge_params_v20(
        self, selected_service: ServiceV20
    ) -> Optional[
        Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ]
    ]:
        """Overrides EVSEControllerInterface.get_ac_charge_params_v20()."""
        ac_charge_parameter_discovery_res_params = ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_max_charge_power
            ),
            evse_max_charge_power_l2=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_max_charge_power_l2
            ),
            evse_max_charge_power_l3=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_max_charge_power_l3
            ),
            evse_min_charge_power=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_min_charge_power
            ),
            evse_min_charge_power_l2=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_min_charge_power_l2
            ),
            evse_min_charge_power_l3=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_min_charge_power_l3
            ),
            evse_nominal_frequency=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_nominal_frequency
            ),
            max_power_asymmetry=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.max_power_asymmetry
            ),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_power_ramp_limit
            ),
            evse_present_active_power=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_present_active_power
            ),
            evse_present_active_power_l2=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_present_active_power_l2  # noqa
            ),
            evse_present_active_power_l3=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.ac_limits.evse_present_active_power_l3  # noqa
            ),
        )
        if selected_service == ServiceV20.AC:
            return ac_charge_parameter_discovery_res_params
        elif selected_service == ServiceV20.AC_BPT:
            return BPTACChargeParameterDiscoveryResParams(
                **(ac_charge_parameter_discovery_res_params.dict()),
                evse_max_discharge_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_max_discharge_power  # noqa
                ),
                evse_max_discharge_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_max_discharge_power_l2  # noqa
                ),
                evse_max_discharge_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_max_discharge_power_l3  # noqa
                ),
                evse_min_discharge_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_min_discharge_power  # noqa
                ),
                evse_min_discharge_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_min_discharge_power_l2  # noqa
                ),
                evse_min_discharge_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.rated_limits.ac_bpt_limits.evse_min_discharge_power_l3  # noqa
                ),
            )
        return None

    async def get_ac_charge_loop_params_v20(
        self, control_mode: ControlMode, selected_service: ServiceV20
    ) -> Union[
        ScheduledACChargeLoopResParams,
        BPTScheduledACChargeLoopResParams,
        DynamicACChargeLoopResParams,
        BPTDynamicACChargeLoopResParams,
    ]:
        """Overrides EVSEControllerInterface.get_ac_charge_loop_params()."""
        if control_mode == ControlMode.SCHEDULED:
            scheduled_params = ScheduledACChargeLoopResParams(
                evse_target_active_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power  # noqa
                ),
                evse_target_active_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power_l2  # noqa
                ),
                evse_target_active_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power_l3  # noqa
                ),
                evse_target_reactive_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power  # noqa
                ),
                evse_target_reactive_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power_l2  # noqa
                ),
                evse_target_reactive_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power_l3  # noqa
                ),
                evse_present_active_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power  # noqa
                ),
                evse_present_active_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power_l2  # noqa
                ),
                evse_present_active_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power_l3  # noqa
                ),
                # Add more optional fields if wanted
            )
            if selected_service == ServiceV20.AC_BPT:
                bpt_scheduled_params = BPTScheduledACChargeLoopResParams(
                    **(scheduled_params.dict()),
                    # Add more optional fields if wanted
                )
                return bpt_scheduled_params
            return scheduled_params
        else:
            # Dynamic Mode
            dynamic_params = DynamicACChargeLoopResParams(
                evse_target_active_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power  # noqa
                ),
                evse_target_active_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power_l2  # noqa
                ),
                evse_target_active_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_active_power_l3  # noqa
                ),
                evse_target_reactive_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power  # noqa
                ),
                evse_target_reactive_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power_l2  # noqa
                ),
                evse_target_reactive_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_target_reactive_power_l3  # noqa
                ),
                evse_present_active_power=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power  # noqa
                ),
                evse_present_active_power_l2=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power_l2  # noqa
                ),
                evse_present_active_power_l3=RationalNumber.get_rational_repr(
                    self.evse_data_context.session_context.ac_limits.evse_present_active_power_l3  # noqa
                ),
            )
            if selected_service == ServiceV20.AC_BPT:
                bpt_dynamic_params = BPTDynamicACChargeLoopResParams(
                    **(dynamic_params.dict()),
                    # Add more optional fields if wanted
                )
                return bpt_dynamic_params
            return dynamic_params

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""
        return DCEVSEStatus(
            evse_notification=EVSENotificationV2.NONE,
            notification_max_delay=0,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        )

    async def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""
        return DCEVSEChargeParameter(
            dc_evse_status=DCEVSEStatus(
                notification_max_delay=100,
                evse_notification=EVSENotificationV2.NONE,
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

    async def get_evse_present_voltage(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentVoltage, RationalNumber]:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            value, exponent = PhysicalValue.get_exponent_value_repr(
                cast(int, self.evse_data_context.session_context.evse_present_voltage)
            )
            try:
                pv_evse_present_voltage = PVEVSEPresentVoltage(
                    multiplier=exponent, value=value, unit="V"
                )
                return pv_evse_present_voltage
            except ValueError:
                return None
        else:
            return RationalNumber.get_rational_repr(
                self.evse_data_context.session_context.evse_present_voltage
            )

    async def get_evse_present_current(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentCurrent, RationalNumber]:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            value, exponent = PhysicalValue.get_exponent_value_repr(
                cast(int, self.evse_data_context.session_context.evse_present_current)
            )
            try:
                pv_evse_present_current = PVEVSEPresentCurrent(
                    multiplier=exponent, value=value, unit="A"
                )
                return pv_evse_present_current
            except ValueError:
                return None
        else:
            return RationalNumber.get_rational_repr(
                self.evse_data_context.session_context.evse_present_current
            )

    async def start_cable_check(self):
        """Overrides EVSEControllerInterface.start_cable_check()."""
        pass

    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """Overrides EVSEControllerInterface.get_cable_check_status()."""
        return IsolationLevel.VALID

    async def set_precharge(
        self,
        voltage: Union[PVEVTargetVoltage, RationalNumber],
        current: Union[PVEVTargetCurrent, RationalNumber],
    ):
        pass

    async def send_charging_command(
        self,
        voltage: Union[PVEVTargetVoltage, RationalNumber],
        charge_current: Union[PVEVTargetCurrent, RationalNumber],
        charge_power: Optional[RationalNumber] = None,
        discharge_current: Optional[RationalNumber] = None,
        discharge_power: Optional[RationalNumber] = None,
    ):
        pass

    async def is_evse_current_limit_achieved(self) -> bool:
        return True

    async def is_evse_voltage_limit_achieved(self) -> bool:
        return True

    async def is_evse_power_limit_achieved(self) -> bool:
        return True

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        return PVEVSEMaxVoltageLimit(multiplier=0, value=600, unit="V")

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        return PVEVSEMaxCurrentLimit(multiplier=0, value=300, unit="A")

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        return PVEVSEMaxPowerLimit(multiplier=1, value=1000, unit="W")

    async def get_dc_charge_params_v20(
        self, selected_service: ServiceV20
    ) -> Union[
        DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
    ]:
        """Override EVSEControllerInterface.get_dc_charge_params_v20()."""
        dc_charge_parameter_discovery_res = DCChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_max_charge_power
            ),
            evse_min_charge_power=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_min_charge_power
            ),
            evse_max_charge_current=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_max_charge_current
            ),
            evse_min_charge_current=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_min_charge_current
            ),
            evse_max_voltage=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_max_voltage
            ),
            evse_min_voltage=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_min_voltage
            ),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(
                self.evse_data_context.rated_limits.dc_limits.evse_power_ramp_limit
            ),
        )
        if selected_service == ServiceV20.DC:
            return dc_charge_parameter_discovery_res
        elif selected_service == ServiceV20.DC_BPT:
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
            logger.error(f"Energy service {selected_service.name} not yet supported")
            return None

    async def get_15118_ev_certificate(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:
        """
        Overrides EVSEControllerInterface.get_15118_ev_certificate().

        Here we simply mock the actions of the backend.
        The code here is almost the same as what is done if USE_CPO_BACKEND
        is set to False. Except that both the request and response is base64 encoded.
        """
        cert_install_req_exi = base64.b64decode(base64_encoded_cert_installation_req)
        cert_install_req = EXI().from_exi(cert_install_req_exi, namespace)
        try:
            dh_pub_key, encrypted_priv_key_bytes = encrypt_priv_key(
                oem_prov_cert=load_cert(CertPath.OEM_LEAF_DER),
                priv_key_to_encrypt=load_priv_key(
                    KeyPath.CONTRACT_LEAF_PEM,
                    KeyEncoding.PEM,
                    KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD,
                ),
            )
        except EncryptionError:
            raise EncryptionError(
                "EncryptionError while trying to encrypt the private key for the "
                "contract certificate"
            )
        except PrivateKeyReadError as exc:
            raise PrivateKeyReadError(
                f"Can't read private key to encrypt for CertificateInstallationRes:"
                f" {exc}"
            )

        # The elements that need to be part of the signature
        contract_cert_chain = CertificateChain(
            id="id1",
            certificate=load_cert(CertPath.CONTRACT_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.MO_SUB_CA2_DER),
                    load_cert(CertPath.MO_SUB_CA1_DER),
                ]
            ),
        )
        encrypted_priv_key = EncryptedPrivateKey(
            id="id2", value=encrypted_priv_key_bytes
        )
        dh_public_key = DHPublicKey(id="id3", value=dh_pub_key)
        emaid = EMAID(
            id="id4", value=get_cert_cn(load_cert(CertPath.CONTRACT_LEAF_DER))
        )
        cps_certificate_chain = CertificateChain(
            certificate=load_cert(CertPath.CPS_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.CPS_SUB_CA2_DER),
                    load_cert(CertPath.CPS_SUB_CA1_DER),
                ]
            ),
        )

        cert_install_res = CertificateInstallationRes(
            response_code=ResponseCodeV2.OK,
            cps_cert_chain=cps_certificate_chain,
            contract_cert_chain=contract_cert_chain,
            encrypted_private_key=encrypted_priv_key,
            dh_public_key=dh_public_key,
            emaid=emaid,
        )

        try:
            # Elements to sign, containing its id and the exi encoded stream
            contract_cert_tuple = (
                cert_install_res.contract_cert_chain.id,
                EXI().to_exi(
                    cert_install_res.contract_cert_chain, Namespace.ISO_V2_MSG_DEF
                ),
            )
            encrypted_priv_key_tuple = (
                cert_install_res.encrypted_private_key.id,
                EXI().to_exi(
                    cert_install_res.encrypted_private_key, Namespace.ISO_V2_MSG_DEF
                ),
            )
            dh_public_key_tuple = (
                cert_install_res.dh_public_key.id,
                EXI().to_exi(cert_install_res.dh_public_key, Namespace.ISO_V2_MSG_DEF),
            )
            emaid_tuple = (
                cert_install_res.emaid.id,
                EXI().to_exi(cert_install_res.emaid, Namespace.ISO_V2_MSG_DEF),
            )

            elements_to_sign = [
                contract_cert_tuple,
                encrypted_priv_key_tuple,
                dh_public_key_tuple,
                emaid_tuple,
            ]
            # The private key to be used for the signature
            signature_key = load_priv_key(
                KeyPath.CPS_LEAF_PEM,
                KeyEncoding.PEM,
                KeyPasswordPath.CPS_LEAF_KEY_PASSWORD,
            )

            signature = create_signature(elements_to_sign, signature_key)

        except PrivateKeyReadError as exc:
            raise Exception(
                "Can't read private key needed to create signature "
                f"for CertificateInstallationRes: {exc}",
            )
        except Exception as exc:
            raise Exception(f"Error creating signature {exc}")

        if isinstance(cert_install_req, CertificateInstallationReq):
            header = MessageHeaderV2(
                session_id=cert_install_req.header.session_id,
                signature=signature,
            )
            body = Body.parse_obj(
                {"CertificateInstallationRes": cert_install_res.dict()}
            )
            to_be_exi_encoded = V2GMessageV2(header=header, body=body)
            exi_encoded_cert_installation_res = EXI().to_exi(
                to_be_exi_encoded, Namespace.ISO_V2_MSG_DEF
            )

            # base64.b64encode in Python is a binary transform
            # so the return value is byte[]
            # But the CPO expects exi_encoded_cert_installation_res
            # as a string, hence the added .decode("utf-8")
            base64_encode_cert_install_res = base64.b64encode(
                exi_encoded_cert_installation_res
            ).decode("utf-8")

            return base64_encode_cert_install_res
        else:
            logger.info(f"Ignoring EXI decoding of a {type(cert_install_req)} message.")
            return ""

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
