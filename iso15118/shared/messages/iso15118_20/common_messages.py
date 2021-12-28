"""
This modules contains classes which implement all the elements of the
ISO 15118-20 XSD file V2G_CI_CommonMessages.xsd (see folder 'schemas').
These are the V2GMessages exchanged between the EVCC and the SECC specifically
for AC charging.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.
"""

from enum import Enum
from typing import List

from pydantic import Field, root_validator, validator

from iso15118.shared.messages import BaseModel
from iso15118.shared.messages.enums import AuthEnum
from iso15118.shared.messages.iso15118_20.common_types import (
    UINT_32_MAX,
    EVSEStatus,
    MeterInfo,
    Processing,
    RationalNumber,
    Receipt,
    RootCertificateID,
    V2GRequest,
    V2GResponse,
)
from iso15118.shared.validators import one_field_must_be_set


class ECDHCurve(str, Enum):
    """
    See section 8.3.5.3.39 in ISO 15118-20.
    Elliptic curves used for the Elliptic Curve Diffie Hellman (ECDH) key
    agreement protocol."""

    secp_521 = "SECP521"
    x448 = "X448"


class EMAID(BaseModel):
    """See Annex C.1 in ISO 15118-20"""

    emaid: str = Field(..., max_length=255, alias="EMAID")


class Certificate(BaseModel):
    """A DER encoded X.509 certificate"""

    certificate: bytes = Field(..., max_length=800, alias="Certificate")


class CertificateChain(BaseModel):
    """See section 8.3.5.3.3 in ISO 15118-20"""

    # Note that the type here must be bytes and not Certificate, otherwise we
    # end up with a json structure that does not match the XSD schema
    certificate: bytes = Field(..., max_length=800, alias="Certificate")
    sub_certificates: List[Certificate] = Field(None, alias="SubCertificates")


class SignedCertificateChain(BaseModel):
    """See section 8.3.5.3.4 in ISO 15118-20"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(..., max_length=255, alias="Id")
    # Note that the type here must be bytes and not Certificate, otherwise we
    # end up with a json structure that does not match the XSD schema
    certificate: bytes = Field(..., max_length=800, alias="Certificate")
    sub_certificates: List[Certificate] = Field(None, alias="SubCertificates")

    def __str__(self):
        return type(self).__name__


class ContractCertificateChain(BaseModel):
    """See section 8.3.5.3.5 in ISO 15118-20"""

    # Note that the type here must be bytes and not Certificate, otherwise we
    # end up with a json structure that does not match the XSD schema
    certificate: bytes = Field(..., max_length=800, alias="Certificate")
    sub_certificates: List[Certificate] = Field(..., alias="SubCertificates")


class SessionSetupReq(V2GRequest):
    """See section 8.3.4.3.1.1 in ISO 15118-20"""

    evcc_id: str = Field(..., max_length=255, alias="EVCCID")


class SessionSetupRes(V2GResponse):
    """See section 8.3.4.3.1.2 in ISO 15118-20"""

    evse_id: str = Field(..., max_length=255, alias="EVSEID")


class AuthorizationSetupReq(V2GRequest):
    """See section 8.3.4.3.2.1 in ISO 15118-20"""


class ProviderID(BaseModel):
    provider_id: str = Field(..., max_length=80, alias="ProviderID")


class PnCAuthSetupResParams(BaseModel):
    """See section 8.3.4.3.2.1 in ISO 15118-20"""

    gen_challenge: bytes = Field(
        ..., min_length=16, max_length=16, alias="GenChallenge"
    )
    supported_providers: List[ProviderID] = Field(
        None, max_items=128, alias="SupportedProviders"
    )


class EIMAuthSetupResParams(BaseModel):
    """See section 8.3.5.3.33 in ISO 15118-20"""


class AuthorizationSetupRes(V2GResponse):
    """See section 8.3.4.3.2.2 in ISO 15118-20"""

    auth_services: List[AuthEnum] = Field(
        ..., max_items=2, alias="AuthorizationServices"
    )
    cert_install_service: bool = Field(..., alias="CertificateInstallationService")
    pnc_as_res: PnCAuthSetupResParams = Field(None, alias="PnC_ASResAuthorizationMode")
    eim_as_res: EIMAuthSetupResParams = Field(None, alias="EIM_ASResAuthorizationMode")

    @root_validator(pre=True)
    def at_least_one_authorization_mode(cls, values):
        """
        At least one of pnc_as_res and eim_as_res must be set, depending on
        whether both Plug & Charge and EIM or just one of these authorization
        modes is offered.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "pnc_as_res",
                "PnC_ASResAuthorizationMode",
                "eim_as_res",
                "EIM_ASResAuthorizationMode",
            ],
            values,
            False,
        ):
            return values


class PnCAuthReqParams(BaseModel):
    """
    See section 8.3.5.3.32 in ISO 15118-20
    PnCAuthReq = Plug and Charge Authorization Request
    """

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(None, max_length=255, alias="Id")
    gen_challenge: bytes = Field(
        ..., min_length=16, max_length=16, alias="GenChallenge"
    )
    contract_cert_chain: ContractCertificateChain = Field(
        ..., alias="ContractCertificateChain"
    )


class EIMAuthReqParams(BaseModel):
    """
    See section 8.3.5.3.31 in ISO 15118-20
    EIMAuthReq = External Identification Means Authorization Request
    """


class AuthorizationReq(V2GRequest):
    """See section 8.3.4.3.3.1 in ISO 15118-20"""

    selected_auth_service: AuthEnum = Field(..., alias="SelectedAuthorizationService")
    pnc_params: PnCAuthReqParams = Field(None, alias="PnC_AReqAuthorizationMode")
    eim_params: EIMAuthReqParams = Field(None, alias="EIM_AReqAuthorizationMode")

    @root_validator(pre=True)
    def at_least_one_authorization_mode(cls, values):
        """
        At least one of pnc_params and eim_params must be set, depending on
        whether both Plug & Charge and EIM or just one of these authorization
        modes is offered.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "pnc_params",
                "PnC_AReqAuthorizationMode",
                "eim_params",
                "EIM_AReqAuthorizationMode",
            ],
            values,
            False,
        ):
            return values


class AuthorizationRes(V2GResponse):
    """See section 8.3.4.3.3.2 in ISO 15118-20"""

    evse_processing: Processing = Field(..., alias="EVSEProcessing")


class ServiceIdList(BaseModel):
    """See section 8.3.5.3.29 in ISO 15118-20"""

    service_id: List[int] = Field(..., max_items=16, alias="ServiceID")


class ServiceDiscoveryReq(V2GRequest):
    """See section 8.3.4.3.4.2 in ISO 15118-20"""

    supported_service_ids: ServiceIdList = Field(..., alias="SupportedServiceIDs")


class ServiceDetails(BaseModel):
    """See section 8.3.5.3.1 in ISO 15118-20"""

    service_id: int = Field(..., alias="ServiceID")
    free_service: bool = Field(..., alias="FreeService")


class Service(BaseModel):
    """See section 8.3.5.3.2 in ISO 15118-20"""

    service_details: ServiceDetails = Field(..., alias="Service")


class ServiceDiscoveryRes(V2GResponse):
    """See section 8.3.4.3.4.3 in ISO 15118-20"""

    service_renegotiation_supported: bool = Field(
        ..., alias="ServiceRenegotiationSupported"
    )
    energy_transfer_service_list: List[Service] = Field(
        ..., max_items=8, alias="EnergyTransferServiceList"
    )
    vas_list: List[Service] = Field(None, max_items=8, alias="VASList")


class ServiceDetailReq(V2GRequest):
    """See section 8.3.4.3.5.1 in ISO 15118-20"""

    service_id: int = Field(..., alias="ServiceID")


class Parameter(BaseModel):
    """See section 8.3.5.3.23 in ISO 15118-20"""

    # 'Name' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    name: str = Field(..., alias="Name")
    bool_value: bool = Field(None, alias="boolValue")
    # XSD type byte with value range [-128..127]
    byte_value: int = Field(None, ge=-128, le=127, alias="byteValue")
    short_value: int = Field(None, ge=0, le=65535, alias="shortValue")
    int_value: int = Field(None, alias="intValue")
    rational_number: RationalNumber = Field(None, alias="rationalNumber")
    finite_str: str = Field(None, alias="finiteString")

    @root_validator(pre=True)
    def at_least_one_parameter_value(cls, values):
        """
        Either bool_value, byte_value, short_value, int_value, rational_number,
        or finite_str must be set, depending on the datatype of the parameter.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "bool_value",
                "boolValue",
                "byte_value",
                "byteValue",
                "short_value",
                "shortValue",
                "int_value",
                "intValue",
                "rational_number",
                "rationalNumber",
                "finite_str",
                "finiteString",
            ],
            values,
            True,
        ):
            return values


class ParameterSet(BaseModel):
    """See section 8.3.5.3.22 in ISO 15118-20"""

    parameter_set_id: int = Field(..., alias="ParameterSetID")
    parameter: List[Parameter] = Field(..., max_items=32, alias="Parameter")


class ServiceParameterList(BaseModel):
    """See section 8.3.5.3.21 in ISO 15118-20"""

    parameter_set: List[ParameterSet] = Field(..., max_items=32, alias="ParameterSet")


class ServiceDetailRes(V2GResponse):
    """See section 8.3.4.3.5.2 in ISO 15118-20"""

    service_id: int = Field(..., alias="ServiceID")
    service_parameter_list: ServiceParameterList = Field(
        ..., alias="ServiceParameterList"
    )


class SelectedService(BaseModel):
    """See section 8.3.5.3.25 in ISO 15118-20"""

    service_id: int = Field(..., alias="ServiceID")
    parameter_set_id: int = Field(..., alias="ParameterSetID")


class SelectedServiceList(BaseModel):
    """See section 8.3.5.3.24 in ISO 15118-20"""

    selected_service: List[SelectedService] = Field(
        ..., max_items=16, alias="SelectedService"
    )


class ServiceSelectionReq(V2GRequest):
    """See section 8.3.4.3.6.2 in ISO 15118-20"""

    selected_energy_transfer_service: SelectedService = Field(
        ..., alias="SelectedEnergyTransferService"
    )
    selected_vas_list: SelectedService = Field(None, alias="SelectedVASList")


class ServiceSelectionRes(V2GResponse):
    """See section 8.3.4.3.6.3 in ISO 15118-20"""


class EVPowerScheduleEntry(BaseModel):
    """See section 8.3.5.3.44 in ISO 15118-20"""

    duration: int = Field(..., alias="Duration")
    power: RationalNumber = Field(..., alias="Power")


class EVPowerScheduleEntryList(BaseModel):
    """See section 8.3.5.3.43 in ISO 15118-20"""

    ev_power_schedule_entry: List[EVPowerScheduleEntry] = Field(
        ..., max_items=1024, alias="EVPowerScheduleEntry"
    )


class EVPowerSchedule(BaseModel):
    """See section 8.3.5.3.42 in ISO 15118-20"""

    time_anchor: int = Field(..., alias="TimeAnchor")
    ev_power_schedule_entries: EVPowerScheduleEntryList = Field(
        ..., alias="EVPowerScheduleEntries"
    )


class EVPriceRule(BaseModel):
    """See section 8.3.5.3.48 in ISO 15118-20"""

    energy_fee: RationalNumber = Field(..., alias="EnergyFee")
    power_range_start: RationalNumber = Field(..., alias="PowerRangeStart")


class EVPriceRuleStack(BaseModel):
    """See section 8.3.5.3.47 in ISO 15118-20"""

    duration: int = Field(..., alias="Duration")
    ev_price_rule: List[EVPriceRule] = Field(..., max_items=8, alias="EVPriceRule")


class EVPriceRuleStackList(BaseModel):
    """See section 8.3.5.3.46 in ISO 15118-20"""

    ev_price_rule_stack: List[EVPriceRuleStack] = Field(
        ..., max_items=1024, alias="EVPriceRuleStack"
    )


class EVAbsolutePriceSchedule(BaseModel):
    """See section 8.3.5.3.45 in ISO 15118-20"""

    time_anchor: int = Field(..., alias="TimeAnchor")
    currency: str = Field(..., max_length=3, alias="Currency")
    price_algorithm: str = Field(..., max_length=255, alias="PriceAlgorithm")
    ev_price_rule_stacks: EVPriceRuleStackList = Field(..., alias="EVPriceRuleStacks")


class EVEnergyOffer(BaseModel):
    """See section 8.3.5.3.41 in ISO 15118-20"""

    ev_power_schedule: EVPowerSchedule = Field(..., alias="EVPowerSchedule")
    ev_absolute_price_schedule: EVAbsolutePriceSchedule = Field(
        ..., alias="EVAbsolutePriceSchedule"
    )


class ScheduledScheduleExchangeReqParams(BaseModel):
    """See section 8.3.5.3.14 in ISO 15118-20"""

    departure_time: int = Field(None, alias="DepartureTime")
    ev_target_energy_request: RationalNumber = Field(
        None, alias="EVTargetEnergyRequest"
    )
    ev_max_energy_request: RationalNumber = Field(None, alias="EVMaximumEnergyRequest")
    ev_min_energy_request: RationalNumber = Field(None, alias="EVMinimumEnergyRequest")
    ev_energy_offer: EVEnergyOffer = Field(None, alias="EVEnergyOffer")


class DynamicScheduleExchangeReqParams(BaseModel):
    """See section 8.3.5.3.13 in ISO 15118-20"""

    departure_time: int = Field(..., alias="DepartureTime")
    # XSD type byte with value range [0..100]
    min_soc: int = Field(None, ge=0, le=100, alias="MinimumSOC")
    # XSD type byte with value range [0..100]
    target_soc: int = Field(None, ge=0, le=100, alias="TargetSOC")
    ev_target_energy_request: RationalNumber = Field(..., alias="EVTargetEnergyRequest")
    ev_max_energy_request: RationalNumber = Field(..., alias="EVMaximumEnergyRequest")
    ev_min_energy_request: RationalNumber = Field(..., alias="EVMinimumEnergyRequest")


class ScheduleExchangeReq(V2GRequest):
    """See section 8.3.4.3.7.2 in ISO 15118-20"""

    max_supporting_points: int = Field(
        ..., ge=12, le=1024, alias="MaximumSupportingPoints"
    )
    scheduled_se_req: ScheduledScheduleExchangeReqParams = Field(
        ..., alias="Scheduled_SEReqControlMode"
    )
    dynamic_se_req: DynamicScheduleExchangeReqParams = Field(
        ..., alias="Dynamic_SEReqControlMode"
    )

    @root_validator(pre=True)
    def either_scheduled_or_dynamic(cls, values):
        """
        Either scheduled_se_req or dynamic_se_req must be set, depending on
        whether the charging process is governed by charging schedules or
        dynamic charging settings from the SECC.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "scheduled_se_req",
                "Scheduled_SEReqControlMode",
                "dynamic_se_req",
                "Dynamic_SEReqControlMode",
            ],
            values,
            True,
        ):
            return values


class PowerScheduleEntry(BaseModel):
    """See section 8.3.5.3.20 in ISO 15118-20"""

    duration: int = Field(..., alias="Duration")
    power: RationalNumber = Field(..., alias="Power")
    power_l2: RationalNumber = Field(None, alias="Power_L2")
    power_l3: RationalNumber = Field(None, alias="Power_L3")


class PowerScheduleEntryList(BaseModel):
    """See section 8.3.5.3.19 in ISO 15118-20"""

    power_schedule_entry: List[PowerScheduleEntry] = Field(
        ..., max_items=1024, alias="PowerScheduleEntry"
    )


class PowerSchedule(BaseModel):
    """See section 8.3.5.3.18 in ISO 15118-20"""

    time_anchor: int = Field(..., alias="TimeAnchor")
    available_energy: RationalNumber = Field(None, alias="AvailableEnergy")
    power_tolerance: RationalNumber = Field(None, alias="PowerTolerance")
    power_schedule_entries: PowerScheduleEntryList = Field(
        ..., alias="PowerScheduleEntries"
    )


class PriceSchedule(BaseModel):
    """See sections 8.3.5.3.49 and 8.3.5.3.62 in ISO 15118-20"""

    time_anchor: int = Field(..., alias="TimeAnchor")
    price_schedule_id: int = Field(..., ge=1, le=UINT_32_MAX, alias="PriceScheduleID")
    price_schedule_description: str = Field(
        None, max_length=160, alias="PriceScheduleDescription"
    )


class PriceLevelScheduleEntry(BaseModel):
    """See section 8.3.5.3.64 in ISO 15118-20"""

    duration: int = Field(..., alias="Duration")
    # XSD type unsignedByte with value range [0..255]
    price_level: int = Field(..., ge=0, le=255, alias="PriceLevel")


class PriceLevelScheduleEntryList(BaseModel):
    """See section 8.3.5.3.63 in ISO 15118-20"""

    entry: List[PriceLevelScheduleEntry] = Field(
        ..., max_items=1024, alias="PriceLevelScheduleEntry"
    )


class PriceLevelSchedule(PriceSchedule):
    """See section 8.3.5.3.62 in ISO 15118-20"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(None, max_length=255, alias="Id")
    # XSD type unsignedByte with value range [0..255]
    num_price_levels: int = Field(..., ge=0, le=255, alias="NumberOfPriceLevels")
    schedule_entries: PriceLevelScheduleEntryList = Field(
        ..., alias="PriceLevelScheduleEntries"
    )


class TaxRule(BaseModel):
    """See section 8.3.5.3.51 in ISO 15118-20"""

    tax_rule_id: int = Field(..., ge=1, le=UINT_32_MAX, alias="TaxRuleID")
    tax_rule_name: str = Field(None, max_length=80, alias="TaxRuleName")
    tax_rate: RationalNumber = Field(..., alias="TaxRate")
    tax_included_in_price: bool = Field(None, alias="TaxIncludedInPrice")
    applies_to_enery_fee: bool = Field(..., alias="AppliesToEnergyFee")
    applies_to_parking_fee: bool = Field(..., alias="AppliesToParkingFee")
    applies_to_overstay_fee: bool = Field(..., alias="AppliesToOverstayFee")
    applies_min_max_cost: bool = Field(..., alias="AppliesMinimumMaximumCost")


class TaxRuleList(BaseModel):
    """See section 8.3.5.3.50 in ISO 15118-20"""

    tax_rule: List[TaxRule] = Field(..., max_items=10, alias="TaxRule")


class PriceRule(BaseModel):
    """See section 8.3.5.3.54 in ISO 15118-20"""

    price_rule_id: int = Field(..., ge=1, le=UINT_32_MAX, alias="PriceRuleID")
    energy_fee: RationalNumber = Field(..., alias="EnergyFee")
    parking_fee: RationalNumber = Field(None, alias="EnergyFee")
    parking_fee_period: int = Field(None, alias="ParkingFeePeriod")
    carbon_dioxide_emission: int = Field(None, alias="CarbonDioxideEmission")
    # XSD type unsignedByte with value range [0..255]
    renewable_energy_percentage: int = Field(
        None, ge=0, le=255, alias="RenewableGenerationPercentage"
    )
    power_range_start: RationalNumber = Field(..., alias="PowerRangeStart")


class PriceRuleStack(BaseModel):
    """See section 8.3.5.3.53 in ISO 15118-20"""

    price_rule_stack_id: int = Field(..., ge=1, le=UINT_32_MAX, alias="PriceRuleStackID")
    duration: int = Field(..., alias="Duration")
    price_rule: List[PriceRule] = Field(..., max_items=8, alias="PriceRule")


class PriceRuleStackList(BaseModel):
    """See section 8.3.5.3.52 in ISO 15118-20"""

    price_rule_stack: List[PriceRuleStack] = Field(
        ..., max_items=1024, alias="PriceRuleStack"
    )


class OverstayRule(BaseModel):
    """See section 8.3.5.3.56 in ISO 15118-20"""

    overstay_rule_id: int = Field(..., ge=1, le=UINT_32_MAX, alias="OverstayRuleID")
    overstay_rule_description: str = Field(
        None, max_length=160, alias="OverstayRuleDescription"
    )
    start_time: int = Field(..., alias="StartTime")
    overstay_fee: RationalNumber = Field(..., alias="OverstayFee")
    overstay_fee_period: int = Field(..., alias="OverstayFeePeriod")


class OverstayRuleList(BaseModel):
    """See section 8.3.5.3.55 in ISO 15118-20"""

    overstay_rule_list_id: int = Field(
        ..., ge=1, le=UINT_32_MAX, alias="OverstayRuleListID"
    )
    overstay_time_threshold: int = Field(None, alias="OverstayTimeThreshold")
    overstay_power_threshold: RationalNumber = Field(
        None, alias="OverstayPowerThreshold"
    )
    overstay_rule: List[OverstayRule] = Field(..., max_items=5, alias="OverstayRule")


class AdditionalService(BaseModel):
    """See section 8.3.5.3.58 in ISO 15118-20"""

    service_name: str = Field(..., max_length=80, alias="ServiceName")
    service_fee: RationalNumber = Field(..., alias="ServiceFee")


class AdditionalServiceList(BaseModel):
    """See section 8.3.5.3.57 in ISO 15118-20"""

    additional_service: List[AdditionalService] = Field(
        ..., max_items=5, alias="AdditionalService"
    )


class AbsolutePriceSchedule(PriceSchedule):
    """See section 8.3.5.3.45 in ISO 15118-20"""

    currency: str = Field(..., max_length=3, alias="Currency")
    language: str = Field(..., max_length=3, alias="Language")
    price_algorithm: str = Field(..., max_length=255, alias="PriceAlgorithm")
    min_cost: RationalNumber = Field(None, alias="MinimumCost")
    max_cost: RationalNumber = Field(None, alias="MaximumCost")
    tax_rules: TaxRuleList = Field(None, alias="TaxRules")
    price_rule_stacks: PriceRuleStackList = Field(..., alias="PriceRuleStacks")
    overstay_rules: OverstayRuleList = Field(None, alias="OverstayRules")
    additional_selected_services: AdditionalServiceList = Field(
        None, alias="AdditionalSelectedServices"
    )


class ChargingSchedule(BaseModel):
    """See section 8.3.5.3.40 in ISO 15118-20"""

    power_schedule: PowerSchedule = Field(..., alias="PowerSchedule")
    price_level_schedule: PriceLevelSchedule = Field(None, alias="PriceLevelSchedule")
    absolute_price_schedule: AbsolutePriceSchedule = Field(
        None, alias="AbsolutePriceSchedule"
    )

    @root_validator(pre=True)
    def either_price_levels_or_absolute_prices(cls, values):
        """
        Either price_level_schedule or absolute_price_schedule must be set,
        depending on whether abstract price levels or absolute prices are used
        to indicate costs for the charging session.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "price_level_schedule",
                "PriceLevelSchedule",
                "absolute_price_schedule",
                "AbsolutePriceSchedule",
            ],
            values,
            True,
        ):
            return values


class DischargingSchedule(BaseModel):
    """See section 8.3.5.3.40 in ISO 15118-20"""

    power_schedule: PowerSchedule = Field(..., alias="PowerSchedule")
    price_level_schedule: PriceLevelSchedule = Field(None, alias="PriceLevelSchedule")
    absolute_price_schedule: AbsolutePriceSchedule = Field(
        None, alias="AbsolutePriceSchedule"
    )

    @root_validator(pre=True)
    def either_price_levels_or_absolute_prices(cls, values):
        """
        Either price_level_schedule or absolute_price_schedule must be set,
        depending on abstract price levels or absolute prices are used to
        indicate costs for the charging session.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "price_level_schedule",
                "PriceLevelSchedule",
                "absolute_price_schedule",
                "AbsolutePriceSchedule",
            ],
            values,
            True,
        ):
            return values


class ScheduleTuple(BaseModel):
    """See section 8.3.5.3.17 in ISO 15118-20"""

    schedule_tuple_id: str = Field(..., max_length=255, alias="ScheduleTupleID")
    charging_schedule: ChargingSchedule = Field(..., alias="ChargingSchedule")
    discharging_schedule: DischargingSchedule = Field(..., alias="DischargingSchedule")


class ScheduledScheduleExchangeResParams(BaseModel):
    """See section 8.3.5.3.16 in ISO 15118-20"""

    schedule_tuple: List[ScheduleTuple] = Field(..., max_items=3, alias="ScheduleTuple")


class DynamicScheduleExchangeResParams(BaseModel):
    """See section 8.3.5.3.15 in ISO 15118-20"""

    departure_time: int = Field(None, alias="DepartureTime")
    # XSD type byte with value range [0..100]
    min_soc: int = Field(None, ge=0, le=100, alias="MinimumSOC")
    # XSD type byte with value range [0..100]
    target_soc: int = Field(None, ge=0, le=100, alias="TargetSOC")
    price_level_schedule: PriceLevelSchedule = Field(None, alias="PriceLevelSchedule")
    absolute_price_schedule: AbsolutePriceSchedule = Field(
        None, alias="AbsolutePriceSchedule"
    )

    @root_validator(pre=True)
    def either_price_levels_or_absolute_prices(cls, values):
        """
        Either price_level_schedule or absolute_price_schedule must be set,
        depending on abstract price levels or absolute prices are used to
        indicate costs for the charging session.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "price_level_schedule",
                "PriceLevelSchedule",
                "absolute_price_schedule",
                "AbsolutePriceSchedule",
            ],
            values,
            True,
        ):
            return values


class ScheduleExchangeRes(V2GResponse):
    """See section 8.3.4.3.7.3 in ISO 15118-20"""

    evse_processing: Processing = Field(..., alias="EVSEProcessing")
    scheduled_se_res: ScheduledScheduleExchangeResParams = Field(
        ..., alias="Scheduled_SEResControlMode"
    )
    dynamic_se_res: DynamicScheduleExchangeResParams = Field(
        ..., alias="Dynamic_SEResControlMode"
    )
    go_to_pause: bool = Field(None, alias="GoToPause")


class EVPowerProfileEntryList(BaseModel):
    """See section 8.3.5.3.10 in ISO 15118-20"""

    ev_power_profile_entry: List[PowerScheduleEntry] = Field(
        ..., max_items=2048, alias="EVPowerProfileEntry"
    )


class PowerToleranceAcceptance(str, Enum):
    """See section 8.3.5.3.12 in ISO 15118-20"""

    power_tolerance_not_confirmed = "PowerToleranceNotConfirmed"
    power_tolerance_confirmed = "PowerToleranceConfirmed"


class ScheduledEVPowerProfile(BaseModel):
    """See section 8.3.5.3.12 in ISO 15118-20"""

    selected_schedule_tuple_id: int = Field(
        ..., ge=1, le=UINT_32_MAX, alias="SelectedScheduleTupleID"
    )
    power_tolerance_acceptance: PowerToleranceAcceptance = Field(
        ..., alias="PowerToleranceAcceptance"
    )


class DynamicEVPowerProfile(BaseModel):
    """See section 8.3.5.3.11 in ISO 15118-20"""


class EVPowerProfile(BaseModel):
    """See section 8.3.5.3.9 in ISO 15118-20"""

    time_anchor: int = Field(..., alias="TimeAnchor")
    ev_power_profile_entries: EVPowerProfileEntryList = Field(
        ..., alias="EVPowerProfileEntries"
    )
    scheduled_ev_power_profile: ScheduledEVPowerProfile = Field(
        None, alias="Scheduled_EVPPTControlMode"
    )
    dynamic_ev_power_profile: DynamicEVPowerProfile = Field(
        None, alias="Dynamic_EVPPTControlMode"
    )

    @root_validator(pre=True)
    def either_scheduled_or_dynamic(cls, values):
        """
        Either scheduled_ev_power_profile or dynamic_ev_power_profile must be
        set, depending on whether the charging process is governed by charging s
        chedules or dynamic charging settings from the SECC.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "scheduled_ev_power_profile",
                "Scheduled_EVPPTControlMode",
                "dynamic_ev_power_profile",
                "Dynamic_EVPPTControlMode",
            ],
            values,
            True,
        ):
            return values


class ChannelSelection(str, Enum):
    """See section 8.3.4.3.8.2 in ISO 15118-20"""

    charge = "Charge"
    discharge = "Discharge"


class ChargeProgress(str, Enum):
    """See section 8.3.4.3.8.2 in ISO 15118-20"""

    start = "Start"
    stop = "Stop"
    standby = "Standby"
    schedule_renegotiation = "ScheduleRenegotiation"


class PowerDeliveryReq(V2GRequest):
    """See section 8.3.4.3.8.2 in ISO 15118-20"""

    ev_processing: Processing = Field(..., alias="EVProcessing")
    charge_progress: ChargeProgress = Field(..., alias="ChargeProgress")
    ev_power_profile: EVPowerProfile = Field(None, alias="EVPowerProfile")
    bpt_channel_selection: ChannelSelection = Field(None, alias="BPT_ChannelSelection")


class PowerDeliveryRes(V2GResponse):
    """See section 8.3.4.3.8.3 in ISO 15118-20"""

    evse_status: EVSEStatus = Field(None, alias="EVSEStatus")


class ScheduledSignedMeterData(BaseModel):
    """See section 8.3.5.3.38 in ISO 15118-20"""

    selected_schedule_tuple_id: int = Field(
        ..., ge=1, le=UINT_32_MAX, alias="SelectedScheduleTupleID"
    )


class DynamicSignedMeterData(BaseModel):
    """See section 8.3.5.3.37 in ISO 15118-20"""


class SignedMeteringData(BaseModel):
    """See section 8.3.5.3.36 in ISO 15118-20"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(..., max_length=255, alias="Id")
    session_id: str = Field(..., max_length=16, alias="SessionID")
    meter_info: MeterInfo = Field(..., alias="MeterInfo")
    receipt: Receipt = Field(None, alias="Receipt")
    scheduled_smart_meter_data: ScheduledSignedMeterData = Field(
        None, alias="Scheduled_SMDTControlMode"
    )
    dynamic_smart_meter_data: DynamicSignedMeterData = Field(
        None, alias="Dynamic_SMDTControlMode"
    )

    @root_validator(pre=True)
    def either_scheduled_or_dynamic(cls, values):
        """
        Either scheduled_smart_meter_data or dynamic_smart_meter_data must be
        set, depending on whether the charging process is governed by charging s
        chedules or dynamic charging settings from the SECC.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "scheduled_smart_meter_data",
                "Scheduled_SMDTControlMode",
                "dynamic_smart_meter_data",
                "Dynamic_SMDTControlMode",
            ],
            values,
            True,
        ):
            return values

        @validator("session_id")
        def check_sessionid_is_hexbinary(cls, value):
            """
            Checks whether the session_id field is a hexadecimal representation of
            8 bytes.

            Pydantic validators are "class methods",
            see https://pydantic-docs.helpmanual.io/usage/validators/
            """
            # pylint: disable=no-self-argument
            # pylint: disable=no-self-use
            try:
                test = int(value, 16)
                return value
            except ValueError as exc:
                raise ValueError(
                    f"Invalid value '{value}' for SessionID (must be "
                    f"hexadecimal representation of max 8 bytes)"
                ) from exc


class MeteringConfirmationReq(V2GRequest):
    """See section 8.3.4.3.11.2 in ISO 15118-20"""

    signed_metering_data: SignedMeteringData = Field(..., alias="SignedMeteringData")


class MeteringConfirmationRes(V2GResponse):
    """See section 8.3.4.3.11.3 in ISO 15118-20"""


class ChargingSession(str, Enum):
    """See section 8.3.4.3.10.2 in ISO 15118-20"""

    pause = "Pause"
    terminate = "Terminate"
    service_renegotiation = "ServiceRenegotiation"


class SessionStopReq(V2GRequest):
    """See section 8.3.4.3.10.2 in ISO 15118-20"""

    charging_session: ChargingSession = Field(..., alias="ChargingSession")
    ev_termination_code: str = Field(..., max_length=80, alias="EVTerminationCode")
    ev_termination_explanation: str = Field(
        ..., max_length=160, alias="EVTerminationExplanation"
    )


class SessionStopRes(V2GResponse):
    """See section 8.3.4.3.10.3 in ISO 15118-20"""


class CertificateInstallationReq(V2GRequest):
    """See section 8.3.4.3.9.2 in ISO 15118-20"""

    oem_prov_cert_chain: SignedCertificateChain = Field(
        ..., alias="OEMProvisioningCertificateChain"
    )
    list_of_root_cert_ids: List[RootCertificateID] = Field(
        ..., max_items=20, alias="ListOfRootCertificateIDs"
    )
    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    max_contract_cert_chains: int = Field(
        ..., ge=0, le=65535, alias="MaximumContractCertificateChains"
    )
    prioritized_emaids: List[EMAID] = Field(
        None, max_items=8, alias="PrioritizedEMAIDs"
    )


class SignedInstallationData(BaseModel):
    """See section 8.3.5.3.39 in ISO 15118-20"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(..., max_length=255, alias="Id")
    contract_cert_chain: ContractCertificateChain = Field(
        ..., alias="ContractCertificateChain"
    )
    ecdh_curve: ECDHCurve = Field(..., alias="ECDHCurve")
    dh_public_key: bytes = Field(..., max_length=133, alias="DHPublicKey")
    secp521_encrypted_private_key: bytes = Field(
        None, min_length=94, max_length=94, alias="SECP521_EncryptedPrivateKey"
    )
    x448_encrypted_private_key: bytes = Field(
        None, min_length=84, max_length=84, alias="X448_EncryptedPrivateKey"
    )
    tpm_encrypted_private_key: bytes = Field(
        None, min_length=209, max_length=209, alias="TPM_EncryptedPrivateKey"
    )

    @root_validator(pre=True)
    def one_encryption_mode(cls, values):
        """
        Either secp521_encrypted_private_key or x448_encrypted_private_key or
        tpm_encrypted_private_key must be set, depending on which encryption
        algorithm is used to encrypt the private key associated with the
        contract certificate.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "secp521_encrypted_private_key",
                "SECP521_EncryptedPrivateKey",
                "x448_encrypted_private_key",
                "X448_EncryptedPrivateKey",
                "tpm_encrypted_private_key",
                "TPM_EncryptedPrivateKey",
            ],
            values,
            True,
        ):
            return values


class CertificateInstallationRes(V2GResponse):
    """See section 8.3.4.3.9.3 in ISO 15118-20"""

    evse_processing: Processing = Field(..., alias="EVSEProcessing")
    cps_certificate_chain: CertificateChain = Field(..., alias="CPSCertificateChain")
    signed_installation_data: SignedInstallationData = Field(
        ..., alias="SignedInstallationData"
    )
    # XSD type unsignedByte with value range [0..255]
    remaining_contract_cert_chains: int = Field(
        ..., ge=0, le=255, alias="RemainingContractCertificateChains"
    )


class EVCheckInStatus(str, Enum):
    """See section 8.3.4.8.1.1.2 in ISO 15118-20"""

    check_in = "CheckIn"
    processing = "Processing"
    completed = "Completed"


class EVCheckOutStatus(str, Enum):
    """See section 8.3.4.8.1.2.2 in ISO 15118-20"""

    check_out = "CheckOut"
    processing = "Processing"
    completed = "Completed"


class EVSECheckOutStatus(str, Enum):
    """See section 8.3.4.8.1.2.3 in ISO 15118-20"""

    scheduled = "Scheduled"
    completed = "Completed"


class ParkingMethod(str, Enum):
    """See section 8.3.4.8.1.1.2 in ISO 15118-20"""

    auto_parking = "AutoParking"
    mv_guided_manual = "MVGuideManual"
    manual = "Manual"


class TargetPosition(BaseModel):
    """Defined in XSD schema but not used in any message"""

    target_offset_x: int = Field(..., alias="TargetOffsetX")
    target_offset_y: int = Field(..., alias="TargetOffsetY")


class VehicleCheckInReq(V2GRequest):
    """See section 8.3.4.8.1.1.2 in ISO 15118-20"""

    ev_check_in_status: EVCheckInStatus = Field(..., alias="EVCheckInStatus")
    parking_method: ParkingMethod = Field(None, alias="ParkingMethod")


class VehicleCheckInRes(V2GResponse):
    """See section 8.3.4.8.1.1.3 in ISO 15118-20"""

    vehicle_space: int = Field(..., alias="VehicleSpace")
    target_offset: TargetPosition = Field(None, alias="TargetOffset")


class VehicleCheckOutReq(V2GRequest):
    """See section 8.3.4.8.1.2.2 in ISO 15118-20"""

    ev_check_out_status: EVCheckOutStatus = Field(..., alias="EVCheckOutStatus")
    check_out_time: int = Field(..., alias="CheckOutTime")


class VehicleCheckOutRes(V2GResponse):
    """See section 8.3.4.8.1.3.2 in ISO 15118-20"""

    evse_check_out_status: EVSECheckOutStatus = Field(..., alias="EVSECheckOutStatus")
