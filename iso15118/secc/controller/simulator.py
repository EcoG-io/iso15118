"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import base64
import logging
import math
import time, calendar
from typing import Dict, List, Optional
import dateutil.parser
import os

from aiofile import async_open
from pydantic import BaseModel, Field

from iso15118.secc.controller.interface import (
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
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from iso15118.shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Namespace,
    PriceAlgorithm,
    Protocol,
    SessionStopAction,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_2.body import Body, CertificateInstallationRes
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
    ResponseCode,
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
from iso15118.shared.messages.iso15118_20.common_types import (
    EVSENotification as EVSENotificationV20,
)
from iso15118.shared.messages.iso15118_20.common_types import EVSEStatus
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
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

from everest_iso15118 import ChargerWrapper
from everest_iso15118 import float2Value_Multiplier
import asyncio

logger = logging.getLogger(__name__)


class V20ServiceParamMapping(BaseModel):
    service_id_parameter_set_mapping: Dict[int, ServiceParameterList] = Field(
        ..., alias="service_id_parameter_set_mapping"
    )


# This method is added to help read the service to parameter
# mapping (json format) from file. The key is in the dictionary is
# enum value of the energy transfer mode and value is the service parameter
async def read_service_id_parameter_mappings():
    try:
        async with async_open(V20_EVSE_SERVICES_CONFIG, "r") as v20_service_config:
            try:
                json_mapping = await v20_service_config.read()
                v20_service_parameter_mapping = V20ServiceParamMapping.parse_raw(
                    json_mapping
                )
                return v20_service_parameter_mapping.service_id_parameter_set_mapping
            except ValueError as exc:
                raise ValueError(
                    f"Error reading 15118-20 service parameters settings file"
                    f" at {V20_EVSE_SERVICES_CONFIG}"
                ) from exc
    except (FileNotFoundError, IOError) as exc:
        raise FileNotFoundError(
            f"V20 config not found at {V20_EVSE_SERVICES_CONFIG}"
        ) from exc


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    @classmethod
    async def create(cls):
        self = SimEVSEController()
        self.evseIsolationMonitoringActive = False
        self.ev_data_context = EVDataContext()
        # self.v20_service_id_parameter_mapping = (
        #     await read_service_id_parameter_mappings()
        # )
        return self

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
            evse_id_din: str = ChargerWrapper.get_EVSEID_DIN()
            return evse_id_din
        else:
            evse_id: str = ChargerWrapper.get_EVSEID()
            return evse_id
        

    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""

        supported_energy_transfer_modes: List[EnergyTransferModeEnum] = []
        for modes in ChargerWrapper.get_SupportedEnergyTransferMode():
            energy_mode = EnergyTransferModeEnum(modes)
            if protocol == Protocol.DIN_SPEC_70121:
                if energy_mode is EnergyTransferModeEnum.DC_CORE or energy_mode is EnergyTransferModeEnum.DC_EXTENDED:
                    supported_energy_transfer_modes.append(energy_mode)
            else:
                supported_energy_transfer_modes.append(energy_mode)

        return supported_energy_transfer_modes

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
        service_ids = [1, 5]
        service_list: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            service_list.services.append(
                Service(service_id=service_id, free_service=False)
            )

        return service_list

    async def is_external_authorization_done(self) -> bool:
        """Overrides EVSEControllerInterface.is_external_authorization_done()."""
        return False

    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationStatus:
        """Overrides EVSEControllerInterface.is_authorized()."""

        if id_token_type is AuthorizationTokenType.EXTERNAL:

            eim_auth_status: bool = ChargerWrapper.get_Auth_Okay_EIM()

            if eim_auth_status is True:
                return AuthorizationStatus.ACCEPTED 

        elif id_token_type is AuthorizationTokenType.EMAID:

            pnc_auth_status: str = ChargerWrapper.get_Auth_PnC_Status()
            certificate_status = ChargerWrapper.get_Auth_Certificate_Status()

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
        ev_charge_params_limits: EVChargeParamsLimits,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTuple] = []

        if departure_time == 0:
            # [V2G2-304] If no departure_time is provided, the sum of the individual
            # time intervals shall be greater than or equal to 24 hours.
            departure_time = 86400

        # PMaxSchedule
        p_max_1 = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
        p_max_2 = PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT)
        p_max_schedule_entry_1 = PMaxScheduleEntry(
            p_max=p_max_1, time_interval=RelativeTimeInterval(start=0)
        )
        p_max_schedule_entry_2 = PMaxScheduleEntry(
            p_max=p_max_2,
            time_interval=RelativeTimeInterval(
                start=math.floor(departure_time / 2),
                duration=math.ceil(departure_time / 2),
            ),
        )
        p_max_schedule = PMaxSchedule(
            schedule_entries=[p_max_schedule_entry_1, p_max_schedule_entry_2]
        )

        # Putting the list of SAScheduleTuple entries together
        sa_schedule_tuple = SAScheduleTuple(
            sa_schedule_tuple_id=1,
            p_max_schedule=p_max_schedule,
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

        powermeter: dict = ChargerWrapper.get_MeterInfo()
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
            if ChargerWrapper.get_contactor_closed_status() is True:
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
            if ChargerWrapper.get_contactor_opened_status() is True:
                return True

            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        return False

    async def get_evse_status(self) -> EVSEStatus:
        """Overrides EVSEControllerInterface.get_evse_status()."""
        return EVSEStatus(
            notification_max_delay=0, evse_notification=EVSENotificationV20.TERMINATE
        )
    
    async def get_receipt_required(self) -> bool:
        return ChargerWrapper.get_ReceiptRequired()

    async def reset_evse_values(self):
        ChargerWrapper.reset()
    
    async def get_evse_payment_options(self) -> list:
        return ChargerWrapper.get_PaymentOptions()

    async def is_free(self) -> bool:
        return ChargerWrapper.get_FreeService()

    async def set_present_protocol_state(self, state_name: str):
        pass

    async def allow_cert_install_service(self) -> bool:
        return ChargerWrapper.get_Certificate_Service_Supported()

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""

        notification : EVSENotificationV2 = EVSENotificationV2.NONE
        if ChargerWrapper.get_stop_charging() is True:
            notification = EVSENotificationV2.STOP_CHARGING

        return ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=notification,
            rcd=ChargerWrapper.get_RCD_Error(),
        )

    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""

        nominal_voltage_value, nominal_voltage_multiplier = float2Value_Multiplier(ChargerWrapper.get_AC_EVSENominalVoltage())
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=nominal_voltage_multiplier, value=nominal_voltage_value, unit=UnitSymbol.VOLTAGE
        )
        max_current_value, max_current_multiplier = float2Value_Multiplier(ChargerWrapper.get_AC_EVSEMaxCurrent())
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=await self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    async def get_ac_charge_params_v20(self) -> ACChargeParameterDiscoveryResParams:
        """Overrides EVSEControllerInterface.get_ac_charge_params_v20()."""
        return ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber(exponent=3, value=11),
            evse_max_charge_power_l2=RationalNumber(exponent=3, value=11),
            evse_max_charge_power_l3=RationalNumber(exponent=3, value=11),
            evse_min_charge_power=RationalNumber(exponent=0, value=100),
            evse_min_charge_power_l2=RationalNumber(exponent=0, value=100),
            evse_min_charge_power_l3=RationalNumber(exponent=0, value=100),
            evse_nominal_frequency=RationalNumber(exponent=0, value=400),
            max_power_asymmetry=RationalNumber(exponent=0, value=500),
            evse_power_ramp_limit=RationalNumber(exponent=0, value=10),
            evse_present_active_power=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l2=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l3=RationalNumber(exponent=3, value=3),
        )

    async def get_ac_bpt_charge_params_v20(
        self,
    ) -> BPTACChargeParameterDiscoveryResParams:
        """Overrides EVSEControllerInterface.get_ac_bpt_charge_params_v20()."""
        ac_charge_params_v20 = (await self.get_ac_charge_params_v20()).dict()
        return BPTACChargeParameterDiscoveryResParams(
            **ac_charge_params_v20,
            evse_max_discharge_power=RationalNumber(exponent=0, value=3000),
            evse_max_discharge_power_l2=RationalNumber(exponent=0, value=3000),
            evse_max_discharge_power_l3=RationalNumber(exponent=0, value=3000),
            evse_min_discharge_power=RationalNumber(exponent=0, value=300),
            evse_min_discharge_power_l2=RationalNumber(exponent=0, value=300),
            evse_min_discharge_power_l3=RationalNumber(exponent=0, value=300),
        )

    async def get_scheduled_ac_charge_loop_params(
        self,
    ) -> ScheduledACChargeLoopResParams:
        """Overrides EVControllerInterface.get_scheduled_ac_charge_loop_params()."""
        return ScheduledACChargeLoopResParams(
            evse_present_active_power=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l2=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l3=RationalNumber(exponent=3, value=3),
            # Add more optional fields if wanted
        )

    async def get_bpt_scheduled_ac_charge_loop_params(
        self,
    ) -> BPTScheduledACChargeLoopResParams:
        """Overrides EVControllerInterface.get_bpt_scheduled_ac_charge_loop_params()."""
        return BPTScheduledACChargeLoopResParams(
            evse_present_active_power=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l2=RationalNumber(exponent=3, value=3),
            evse_present_active_power_l3=RationalNumber(exponent=3, value=3),
            # Add more optional fields if wanted
        )

    async def get_dynamic_ac_charge_loop_params(self) -> DynamicACChargeLoopResParams:
        """Overrides EVControllerInterface.get_dynamic_ac_charge_loop_params()."""
        return DynamicACChargeLoopResParams(
            evse_target_active_power=RationalNumber(exponent=3, value=3),
            evse_target_active_power_l2=RationalNumber(exponent=3, value=3),
            evse_target_active_power_l3=RationalNumber(exponent=3, value=3),
            # Add more optional fields if wanted
        )

    async def get_bpt_dynamic_ac_charge_loop_params(
        self,
    ) -> BPTDynamicACChargeLoopResParams:
        """Overrides EVControllerInterface.get_bpt_dynamic_ac_charge_loop_params()."""
        return BPTDynamicACChargeLoopResParams(
            evse_target_active_power=RationalNumber(exponent=3, value=3),
            evse_target_active_power_l2=RationalNumber(exponent=3, value=3),
            evse_target_active_power_l3=RationalNumber(exponent=3, value=3),
            # Add more optional fields if wanted
        )

    async def get_ac_evse_max_current(self) -> PVEVSEMaxCurrent:
        max_current_value, max_current_multiplier = float2Value_Multiplier(ChargerWrapper.get_AC_EVSEMaxCurrent())
        return PVEVSEMaxCurrent( multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE)

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""

        notification : EVSENotificationV2 = EVSENotificationV2.NONE
        if ChargerWrapper.get_stop_charging() is True:
            notification = EVSENotificationV2.STOP_CHARGING
        
        evse_isolation : IsolationLevel = IsolationLevel(ChargerWrapper.get_EVSEIsolationStatus())
        
        evse_status_code: DCEVSEStatusCode = DCEVSEStatusCode.EVSE_READY
        if ChargerWrapper.get_EVSE_UtilityInterruptEvent() is True:
            evse_status_code = DCEVSEStatusCode.EVSE_UTILITY_INTERUPT_EVENT
        elif ChargerWrapper.get_EVSE_Malfunction() is True:
            evse_status_code = DCEVSEStatusCode.EVSE_MALFUNCTION
        elif ChargerWrapper.get_EVSE_EmergencyShutdown() is True:
            evse_status_code = DCEVSEStatusCode.EVSE_EMERGENCY_SHUTDOWN
        elif self.evseIsolationMonitoringActive is True:
            evse_status_code = DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
        elif ChargerWrapper.get_stop_charging() is True:
            evse_status_code = DCEVSEStatusCode.EVSE_SHUTDOWN

        return DCEVSEStatus(
            evse_notification=notification,
            notification_max_delay=0,
            evse_isolation_status=evse_isolation,
            evse_status_code=evse_status_code,
        )
		
    async def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""

        c_ripple_value, c_ripple_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEPeakCurrentRipple()
        )
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumCurrentLimit()
        )
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumPowerLimit()
        )
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumVoltageLimit()
        )
        c_min_limit_value, c_min_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMinimumCurrentLimit()
        )
        v_min_limit_value, v_min_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMinimumVoltageLimit()
        )

        dcEVSEChargeParameter: DCEVSEChargeParameter = DCEVSEChargeParameter(
            dc_evse_status= await self.get_dc_evse_status(),
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

        if ChargerWrapper.get_DC_EVSECurrentRegulationTolerance() is not None:
            current_reg_tol_value, current_reg_tol_multiplier = float2Value_Multiplier(
                ChargerWrapper.get_DC_EVSECurrentRegulationTolerance()
            )
            dcEVSEChargeParameter.evse_current_regulation_tolerance = PVEVSECurrentRegulationTolerance(
                multiplier=current_reg_tol_multiplier, value=current_reg_tol_value, unit="A"
            )
        if ChargerWrapper.get_EVSEEnergyToBeDelivered() is not None:
            energy_deliver_value, energy_deliver_multiplier = float2Value_Multiplier(
                ChargerWrapper.get_EVSEEnergyToBeDelivered()
            )
            dcEVSEChargeParameter.evse_energy_to_be_delivered = PVEVSEEnergyToBeDelivered(
                multiplier = energy_deliver_multiplier, value = energy_deliver_value, unit="Wh"
            )

        return dcEVSEChargeParameter

    async def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        v_value, v_multiplier = float2Value_Multiplier(ChargerWrapper.get_DC_EVSEPresentVoltage())
        return PVEVSEPresentVoltage(multiplier=v_multiplier, value=v_value, unit="V")

    async def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        c_value, c_multiplier = float2Value_Multiplier(ChargerWrapper.get_DC_EVSEPresentCurrent())
        return PVEVSEPresentCurrent(multiplier=c_multiplier, value=c_value, unit="A")

    async def start_cable_check(self):
        pass

    async def set_precharge(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        pass

    async def send_charging_command(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        pass

    async def is_evse_current_limit_achieved(self) -> bool:
        if ChargerWrapper.get_DC_EVSEPresentCurrent() >= ChargerWrapper.get_DC_EVSEMaximumCurrentLimit():
            return True
        return False

    async def is_evse_voltage_limit_achieved(self) -> bool:
        if ChargerWrapper.get_DC_EVSEPresentVoltage() >= ChargerWrapper.get_DC_EVSEMaximumVoltageLimit():
            return True
        return False

    async def is_evse_power_limit_achieved(self) -> bool:
        presentPower:float = ChargerWrapper.get_DC_EVSEPresentCurrent() * ChargerWrapper.get_DC_EVSEPresentVoltage()
        if presentPower >= ChargerWrapper.get_DC_EVSEMaximumPowerLimit():
            return True
        return False

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumVoltageLimit()
        )
        return PVEVSEMaxVoltageLimit(multiplier=v_max_limit_multiplier, value=v_max_limit_value, unit="V")

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumCurrentLimit()
        )
        return PVEVSEMaxCurrentLimit(multiplier=c_max_limit_multiplier, value=c_max_limit_value, unit="A")

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
            ChargerWrapper.get_DC_EVSEMaximumPowerLimit()
        )
        return PVEVSEMaxPowerLimit(multiplier=p_max_limit_multiplier, value=p_max_limit_value, unit="W")

    async def get_dc_charge_params_v20(self) -> DCChargeParameterDiscoveryResParams:
        """Overrides EVSEControllerInterface.get_dc_charge_params_v20()."""
        return DCChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber(exponent=3, value=300),
            evse_min_charge_power=RationalNumber(exponent=0, value=100),
            evse_max_charge_current=RationalNumber(exponent=0, value=300),
            evse_min_charge_current=RationalNumber(exponent=0, value=10),
            evse_max_voltage=RationalNumber(exponent=0, value=1000),
            evse_min_voltage=RationalNumber(exponent=0, value=10),
            evse_power_ramp_limit=RationalNumber(exponent=0, value=10),
        )

    async def get_dc_bpt_charge_params_v20(
        self,
    ) -> BPTDCChargeParameterDiscoveryResParams:
        """Overrides EVSEControllerInterface.get_dc_bpt_charge_params_v20()."""
        return BPTDCChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber(exponent=3, value=300),
            evse_min_charge_power=RationalNumber(exponent=0, value=100),
            evse_max_charge_current=RationalNumber(exponent=0, value=300),
            evse_min_charge_current=RationalNumber(exponent=0, value=10),
            evse_max_voltage=RationalNumber(exponent=0, value=1000),
            evse_min_voltage=RationalNumber(exponent=0, value=10),
            evse_max_discharge_power=RationalNumber(exponent=3, value=11),
            evse_min_discharge_power=RationalNumber(exponent=3, value=1),
            evse_max_discharge_current=RationalNumber(exponent=0, value=11),
            evse_min_discharge_current=RationalNumber(exponent=0, value=0),
        )
    
    async def setIsolationMonitoringActive(self, value: bool):
        self.evseIsolationMonitoringActive = value
    
    async def isCableCheckFinished(self) -> bool:
        return ChargerWrapper.get_cableCheck_Finished()

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

            Response: dict = ChargerWrapper.get_Certificate_Response()
            if Response:
                if Response["certificateAction"] == "Install":
                    if Response["status"] == "Accepted":
                        exiResponse: str = str(Response["exiResponse"])
                        return exiResponse
                    elif Response["status"] == "Failed":
                        raise Exception("The CSMS reported: Processing of the message was not successful")
                elif Response["certificateAction"] == "Update":
                    action: str = str(Response["certificateAction"])
                    raise Exception(f"The wrong message was generated by the backend: {action}")
                
            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        
        raise Exception("Timeout - The backend takes too long to generate the CertificateInstallationRes")

    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Overrides EVSEControllerInterface.update_data_link().
        """
        pass
