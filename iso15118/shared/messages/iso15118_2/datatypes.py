"""
This modules contains classes which implement all the elements of the
ISO 15118-2 XSD file V2G_CI_DataTypes.xsd (see folder 'schemas').
These are the data types used by both the header and the body elements of the
V2GMessages exchanged between the EVCC and the SECC.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.
"""

from enum import Enum, IntEnum
from typing import List, Literal

from pydantic import Field, root_validator, validator

from iso15118.shared.messages import BaseModel
from iso15118.shared.messages.enums import (
    INT_8_MAX,
    INT_8_MIN,
    INT_16_MAX,
    INT_16_MIN,
    UINT_32_MAX,
    AuthEnum,
)
from iso15118.shared.messages.xmldsig import X509IssuerSerial
from iso15118.shared.validators import one_field_must_be_set


class UnitSymbol(str, Enum):
    """
    These are the physical units used in the PhysicalValue subclasses.
    See Table 68 in section 8.5.2.7 in ISO 15118-2.
    """

    HOURS = "h"
    MINUTES = "m"
    SECONDS = "s"
    AMPERE = "A"
    VOLTAGE = "V"
    WATT = "W"
    WATT_HOURS = "Wh"


class PhysicalValue(BaseModel):
    """
    All classes inheriting from PhysicalValue start with 'PV'
    (abbreviation for 'Physical Value') and define value and unit fields.
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Those classes also inherit the private attribute `_max_limit`, which is used
    to set the maximum limit of each specific physical type and used in the
    `validate_value_range` method. This private attribute is not added to the
    Pydantic model in anyway: https://github.com/samuelcolvin/pydantic/issues/655

    The minimum limit is fixed to 0, as in ISO 15118-2 there are no PhysicalValues
    that can go below that value.
    """

    _max_limit: int = 0
    # XSD int16 range [-32768, 32767]
    value: int = Field(..., ge=INT_16_MIN, le=INT_16_MAX, alias="Value")
    # XSD type byte with value range [-3..3]
    multiplier: int = Field(..., ge=-3, le=3, alias="Multiplier")

    @root_validator
    def validate_value_range(cls, values):
        """
        Validator for the range of the PhysicalValue type

        Raises:
            ValueError, if the calculated value exceeds the limits set
        """
        value = values.get("value")
        multiplier = values.get("multiplier")
        calculated_value = value * 10 ** multiplier
        if calculated_value > cls._max_limit or calculated_value < 0:
            raise ValueError(
                f"{cls.__name__[2:]} value limit exceeded: {calculated_value} \n"
                f"Max: {cls._max_limit} \n"
                f"Min: 0"
            )
        return values


class PVChargingProfileEntryMaxPower(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for ChargingProfileEntryMaxPower.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEAmount(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for EAmount.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVEnergyCapacity(PhysicalValue):
    """
     See Table 68 in section 8.5.2.7 in ISO 15118-2

     Value is of XSD type short (16 bit integer) with value range [-32768..32767].
     But Table 68 shows a max value of 200000 for EVEnergyCapacity.
    Therefore, you'll have to use the multiplier to reach the max value
     (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVEnergyRequest(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for EVEnergyRequest.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVMaxCurrent(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2
    """

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVMaxCurrentLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVMaxPowerLimit(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for EVMaxPowerLimit.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEVMaxVoltage(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVMaxVoltageLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVMinCurrent(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSECurrentRegulationTolerance(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEEnergyToBeDelivered(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for EVSEEnergyToBeDelivered.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVSEMaxCurrent(PhysicalValue):
    """See sections 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMaxCurrentLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMaxPowerLimit(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2

    Value is of XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for EVSEMaxPowerLimit.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEVSEMaxVoltageLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSENominalVoltage(PhysicalValue):
    """See section 8.5.2.7  in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSEMinCurrentLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMinVoltageLimit(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSEPeakCurrentRipple(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEPresentCurrent(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEPresentVoltage(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVTargetCurrent(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVTargetVoltage(PhysicalValue):
    """See Table 68 in section 8.5.2.7 in ISO 15118-2"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVPMax(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2
    XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for PMax.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVRemainingTimeToBulkSOC(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2
    XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 172800 for RemainingTimeToBulkSOC.
    Therefore, you'll have to use the multiplier to reach the max value
    (multiplier = 2 and value = 1728 => 1728 * 10 ^ 2)
    """

    _max_limit: int = 172800
    unit: Literal[UnitSymbol.SECONDS] = Field(..., alias="Unit")


class PVRemainingTimeToFullSOC(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2
    XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 172800 for RemainingTimeToFullSOC.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 2 and value = 1728 => 1728 * 10 ^ 2)
    """

    _max_limit: int = 172800
    unit: Literal[UnitSymbol.SECONDS] = Field(..., alias="Unit")


class PVStartValue(PhysicalValue):
    """
    See Table 68 in section 8.5.2.7 in ISO 15118-2
    XSD type short (16 bit integer) with value range [-32768..32767].
    But Table 68 shows a max value of 200000 for StartValue.
    Therefore, you'll have to use the multiplier to reach the max value
    (e.g. multiplier = 3 and value = 200 => 200 * 10 ^ 3)
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class EVChargeParameter(BaseModel):
    """See section 8.4.3.8.2 in ISO 15118-2"""

    # XSD type unsignedInt (32-bit unsigned integer) with value range
    departure_time: int = Field(None, ge=0, le=UINT_32_MAX, alias="DepartureTime")


class ACEVChargeParameter(EVChargeParameter):
    """See section 8.5.3.2 in ISO 15118-2"""

    e_amount: PVEAmount = Field(..., alias="EAmount")
    ev_max_voltage: PVEVMaxVoltage = Field(..., alias="EVMaxVoltage")
    ev_max_current: PVEVMaxCurrent = Field(..., alias="EVMaxCurrent")
    ev_min_current: PVEVMinCurrent = Field(..., alias="EVMinCurrent")


class EVSENotification(str, Enum):
    """See sections 8.5.3.1 and 8.5.4.1 in ISO 15118-2"""

    NONE = "None"
    STOP_CHARGING = "StopCharging"
    RE_NEGOTIATION = "ReNegotiation"


class EVSEStatus(BaseModel):
    """See sections 8.5.3.1 and 8.5.4.1 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    notification_max_delay: int = Field(
        ..., ge=0, le=65535, alias="NotificationMaxDelay"
    )
    evse_notification: EVSENotification = Field(..., alias="EVSENotification")


class ACEVSEStatus(EVSEStatus):
    """See section 8.5.3.1 in ISO 15118-2"""

    rcd: bool = Field(..., alias="RCD")


class ACEVSEChargeParameter(BaseModel):
    """See section 8.5.3.3 in ISO 15118-2"""

    ac_evse_status: ACEVSEStatus = Field(..., alias="AC_EVSEStatus")
    evse_nominal_voltage: PVEVSENominalVoltage = Field(..., alias="EVSENominalVoltage")
    evse_max_current: PVEVSEMaxCurrent = Field(..., alias="EVSEMaxCurrent")


class Certificate(BaseModel):
    """See sections 8.5.2.5 and 8.5.2.26 in ISO 15118-2"""

    certificate: bytes = Field(..., max_length=800, alias="Certificate")


class CertificateChain(BaseModel):
    """See section 8.5.2.5 in ISO 15118-2"""

    id: str = Field(None, alias="Id")
    # Note that the type here must be bytes and not Certificate, otherwise we
    # end up with a json structure that does not match the XSD schema
    certificate: bytes = Field(..., max_length=800, alias="Certificate")
    sub_certificates: List[Certificate] = Field(None, alias="SubCertificates")

    def __str__(self):
        return type(self).__name__


class ChargeProgress(str, Enum):
    """See section 8.4.3.9.2 in ISO 15118-2"""

    START = "Start"
    STOP = "Stop"
    RENEGOTIATE = "Renegotiate"


class EnergyTransferModeEnum(str, Enum):
    """See sections 8.5.2.4 and 8.4.3.8.2 in ISO 15118-2"""

    AC_SINGLE_PHASE_CORE = "AC_single_phase_core"
    AC_THREE_PHASE_CORE = "AC_three_phase_core"
    DC_CORE = "DC_core"
    DC_EXTENDED = "DC_extended"
    DC_COMBO_CORE = "DC_combo_core"
    DC_UNIQUE = "DC_unique"


class EnergyTransferModeList(BaseModel):
    """See section 8.5.2.4 in ISO 15118-2"""

    energy_modes: List[EnergyTransferModeEnum] = Field(..., max_items=6,
                                                       alias="EnergyTransferMode")


class ServiceID(IntEnum):
    """See section 8.4.3.3.2 in ISO 15118-2"""

    CHARGING = 1
    CERTIFICATE = 2
    INTERNET = 3
    # There's conflicting information in the standard. Annex C.6 (page 269)
    # lists this as 'OtherCustom', but Table 105 lists this as 'EVSEInformation'
    # ("Service enabling the exchange of use case specific information about
    # the EVSE"). No idea what they mean by that, so we go with 'OtherCustom'.
    CUSTOM = 4


class ServiceCategory(str, Enum):
    """See section 8.4.3.3.2 in ISO 15118-2"""

    CHARGING = "EVCharging"
    CERTIFICATE = "ContractCertificate"
    INTERNET = "Internet"
    CUSTOM = "OtherCustom"


class ServiceName(str, Enum):
    """See section 8.6.3.6, Table 105 in ISO 15118-2"""

    CHARGING = "AC_DC_Charging"
    CERTIFICATE = "Certificate"
    INTERNET = "InternetAccess"
    CUSTOM = "UseCaseInformation"


class ServiceDetails(BaseModel):
    """See section 8.5.2.1 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    service_id: ServiceID = Field(..., ge=0, le=65535, alias="ServiceID")
    service_name: ServiceName = Field(None, max_length=32, alias="ServiceName")
    service_category: ServiceCategory = Field(..., alias="ServiceCategory")
    service_scope: str = Field(None, max_length=64, alias="ServiceScope")
    free_service: bool = Field(..., alias="FreeService")


class ChargeService(ServiceDetails):
    """See section 8.5.2.3 in ISO 15118-2"""

    supported_energy_transfer_mode: EnergyTransferModeList = Field(
        ..., alias="SupportedEnergyTransferMode"
    )


class ProfileEntryDetails(BaseModel):
    """See section 8.5.2.11 in ISO 15118-2"""

    start: int = Field(..., alias="ChargingProfileEntryStart")
    max_power: PVPMax = Field(..., alias="ChargingProfileEntryMaxPower")
    # XSD type byte with value range [1..3]
    max_phases_in_use: int = Field(
        None, ge=1, le=3, alias="ChargingProfileEntryMaxNumberOfPhasesInUse"
    )


class ProfileEntry(BaseModel):
    """See section 8.5.2.10 in ISO 15118-2"""

    entry_details: ProfileEntryDetails = Field(..., alias="ProfileEntry")


class ChargingSession(str, Enum):
    """See section 8.4.3.12.2 in ISO 15118-2"""

    TERMINATE = "Terminate"
    PAUSE = "Pause"


class CostKind(str, Enum):
    """See section 8.5.2.20 in ISO 15118-2"""

    RELATIVE_PRICE_PERCENTAGE = "relativePricePercentage"
    RENEWABLE_GENERATION_PERCENTAGE = "RenewableGenerationPercentage"
    CARBON_DIOXIDE_EMISSION = "CarbonDioxideEmission"


class Cost(BaseModel):
    """See section 8.5.2.20 in ISO 15118-2"""

    cost_kind: CostKind = Field(..., alias="costKind")
    amount: int = Field(..., alias="amount")
    # XSD type byte with value range [-3..3]
    amount_multiplier: int = Field(None, ge=-3, le=3, alias="amountMultiplier")


class ConsumptionCost(BaseModel):
    """See section 8.5.2.19 in ISO 15118-2"""

    start_value: PVStartValue = Field(..., alias="startValue")
    cost: List[Cost] = Field(..., max_items=3, alias="Cost")


class EncryptedPrivateKey(BaseModel):
    """See section 8.5.2.28 in ISO 15118-2"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(..., alias="Id")
    # The XSD doesn't explicitly state a Value element for
    # ContractSignatureEncryptedPrivateKeyType but its base XSD type named
    # privateKeyType has an XSD element <xs:maxLength value="48"/>. That's why
    # we add this 'value' field
    value: bytes = Field(..., max_length=48, alias="value")

    def __str__(self):
        # The XSD conform element name
        return "ContractSignatureEncryptedPrivateKey"


class DCEVErrorCode(str, Enum):
    """See section 8.5.4.2 in ISO 15118-2"""

    NO_ERROR = "NO_ERROR"
    FAILED_RESS_TEMPERATURE_INHIBIT = "FAILED_RESSTemperatureInhibit"
    FAILED_EV_SHIFT_POSITION = "FAILED_EVShiftPosition"
    FAILED_CHARGER_CONNECTOR_LOCK_FAULT = "FAILED_ChargerConnectorLockFault"
    FAILED_EV_RESS_MALFUNCTION = "FAILED_EVRESSMalfunction"
    FAILED_CHARGING_CURRENT_DIFFERENTIAL = "FAILED_ChargingCurrentdifferential"
    FAILED_CHARGING_VOLTAGE_OUT_OF_RANGE = "FAILED_ChargingVoltageOutOfRange"
    FAILED_CHARGING_SYSTEM_INCOMPATIBILITY = "FAILED_ChargingSystemIncompatibility"
    NO_DATA = "NoData"
    RESERVED_A = "Reserved_A"
    RESERVED_B = "Reserved_B"
    RESERVED_C = "Reserved_C"


class DCEVStatus(BaseModel):
    """See section 8.5.4.2 in ISO 15118-2"""

    ev_ready: bool = Field(..., alias="EVReady")
    ev_error_code: DCEVErrorCode = Field(..., alias="EVErrorCode")
    # XSD type byte with value range [0..100]
    ev_ress_soc: int = Field(..., ge=0, le=100, alias="EVRESSSOC")


class DCEVChargeParameter(EVChargeParameter):
    """See section 8.5.4.3 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_maximum_current_limit: PVEVMaxCurrentLimit = Field(
        ..., alias="EVMaximumCurrentLimit"
    )
    ev_maximum_power_limit: PVEVMaxPowerLimit = Field(None, alias="EVMaximumPowerLimit")
    ev_maximum_voltage_limit: PVEVMaxVoltageLimit = Field(
        ..., alias="EVMaximumVoltageLimit"
    )
    ev_energy_capacity: PVEVEnergyCapacity = Field(None, alias="EVEnergyCapacity")
    ev_energy_request: PVEVEnergyRequest = Field(None, alias="EVEnergyRequest")
    # XSD type byte with value range [0..100]
    full_soc: int = Field(None, ge=0, le=100, alias="FullSOC")
    # XSD type byte with value range [0..100]
    bulk_soc: int = Field(None, ge=0, le=100, alias="BulkSOC")


class DCEVPowerDeliveryParameter(BaseModel):
    """See section 8.5.4.5 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    bulk_charging_complete: bool = Field(None, alis="BulkChargingComplete")
    charging_complete: bool = Field(..., alias="ChargingComplete")


class DCEVSEStatusCode(str, Enum):
    """See section 8.5.4.1 in ISO 15118-2"""

    EVSE_NOT_READY = "EVSE_NotReady"
    EVSE_READY = "EVSE_Ready"
    EVSE_SHUTDOWN = "EVSE_Shutdown"
    # XSD typo in "Interrupt"
    EVSE_UTILITY_INTERUPT_EVENT = "EVSE_UtilityInterruptEvent"
    EVSE_ISOLATION_MONITORING_ACTIVE = "EVSE_IsolationMonitoringActive"
    EVSE_EMERGENCY_SHUTDOWN = "EVSE_EmergencyShutdown"
    EVSE_MALFUNCTION = "EVSE_Malfunction"
    RESERVED_8 = "Reserved_8"
    RESERVED_9 = "Reserved_9"
    RESERVED_A = "Reserved_A"
    RESERVED_B = "Reserved_B"
    RESERVED_C = "Reserved_C"


class IsolationLevel(str, Enum):
    """See section 8.5.4.1 in ISO 15118-2"""

    INVALID = "Invalid"
    VALID = "Valid"
    WARNING = "Warning"
    FAULT = "Fault"
    NO_IMD = "No_IMD"


class DCEVSEStatus(EVSEStatus):
    """See section 8.5.4.1 in ISO 15118-2"""

    evse_isolation_status: IsolationLevel = Field(None, alias="EVSEIsolationStatus")
    evse_status_code: DCEVSEStatusCode = Field(..., alias="EVSEStatusCode")


class DCEVSEChargeParameter(BaseModel):
    """See section 8.5.4.4 in ISO 15118-2"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_maximum_current_limit: PVEVSEMaxCurrentLimit = Field(
        ..., alias="EVSEMaximumCurrentLimit"
    )
    evse_maximum_power_limit: PVEVSEMaxPowerLimit = Field(
        ..., alias="EVSEMaximumPowerLimit"
    )
    evse_maximum_voltage_limit: PVEVSEMaxVoltageLimit = Field(
        ..., alias="EVSEMaximumVoltageLimit"
    )
    evse_minimum_current_limit: PVEVSEMinCurrentLimit = Field(
        ..., alias="EVSEMinimumCurrentLimit"
    )
    evse_minimum_voltage_limit: PVEVSEMinVoltageLimit = Field(
        ..., alias="EVSEMinimumVoltageLimit"
    )
    evse_current_regulation_tolerance: PVEVSECurrentRegulationTolerance = Field(
        None, alias="EVSECurrentRegulationTolerance"
    )
    evse_peak_current_ripple: PVEVSEPeakCurrentRipple = Field(
        ..., alias="EVSEPeakCurrentRipple"
    )
    evse_energy_to_be_delivered: PVEVSEEnergyToBeDelivered = Field(
        None, alias="EVSEEnergyToBeDelivered"
    )


class DHPublicKey(BaseModel):
    """See section 8.5.2.29 in ISO 15118-2"""

    id: str = Field(..., alias="Id")
    value: bytes = Field(..., max_length=65, alias="value")

    def __str__(self):
        # The XSD has a typo here, not using pascal case for the datatype
        return "DHpublickey"


class EVSEProcessing(str, Enum):
    """See sections 8.4.3.8.3, 8.4.3.7.2, and 8.4.5.2.3 in ISO 15118-2"""

    FINISHED = "Finished"
    ONGOING = "Ongoing"
    ONGOING_WAITING_FOR_CUSTOMER = "Ongoing_WaitingForCustomerInteraction"


class FaultCode(str, Enum):
    """See section 8.5.2.8 in ISO 15118-2"""

    PARSING_ERROR = "ParsingError"
    # Typo in XSD file ("Certificat")
    NO_TLS_ROOT_CERTIFICATE_AVAILABLE = "NoTLSRootCertificatAvailable"
    UNKNOWN_ERROR = "UnknownError"


class RootCertificateID(BaseModel):
    """See section 8.5.2.27 in ISO 15118-2"""

    x509_issuer_serial: X509IssuerSerial = Field(..., alias="RootCertificateID")


class MeterInfo(BaseModel):
    """See section 8.5.2.27 in ISO 15118-2"""

    meter_id: str = Field(..., max_length=32, alias="MeterID")
    meter_reading: int = Field(None, ge=0, le=999999999, alias="MeterReading")
    sig_meter_reading: bytes = Field(None, max_length=64, alias="SigMeterReading")
    # XSD type short (16 bit integer) with value range [-32768..32767]
    # A status with a negative value doesn't make much sense though ...
    meter_status: int = Field(None, ge=INT_16_MIN, le=INT_16_MAX, alias="MeterStatus")
    # XSD type short (16 bit integer) with value range [-32768..32767].
    # However, that doesn't make any sense as TMeter is supposed to be a Unix
    # time stamp. Should be unsignedLong
    t_meter: int = Field(None, alias="TMeter")


class Notification(BaseModel):
    """See section 8.5.2.8 in ISO 15118-2"""

    fault_code: FaultCode = Field(..., alias="FaultCode")
    fault_msg: str = Field(None, max_length=64, alias="FaultMsg")

    def __str__(self):
        additional_info = f" ({self.fault_msg})" if self.fault_msg else ""
        return self.fault_code + additional_info


class Parameter(BaseModel):
    """See section 8.5.2.23 in ISO 15118-2"""

    # 'Name' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    name: str = Field(..., alias="Name")
    bool_value: bool = Field(None, alias="boolValue")
    # XSD type byte with value range [-128..127]
    byte_value: int = Field(None, ge=INT_8_MIN, le=INT_8_MAX, alias="byteValue")
    # XSD type short (16 bit integer) with value range [-32768..32767]
    short_value: int = Field(None, ge=INT_16_MIN, le=INT_16_MAX, alias="shortValue")
    int_value: int = Field(None, alias="intValue")
    physical_value: PhysicalValue = Field(None, alias="physicalValue")
    str_value: str = Field(None, alias="stringValue")

    @root_validator(pre=True)
    def at_least_one_parameter_value(cls, values):
        """
        Either bool_value, byte_value, short_value, int_value, physical_value,
        or str_value must be set, depending on the datatype of the parameter.

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
                "physical_value",
                "physicalValue",
                "str_value",
                "stringValue",
            ],
            values,
            True,
        ):
            return values


class ParameterSet(BaseModel):
    """See section 8.5.2.22 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    # Table 87 says short, Table 106 says unsignedShort. We go with
    # unsignedShort as it makes more sense (no negative values).
    parameter_set_id: int = Field(..., ge=0, le=65535, alias="ParameterSetID")
    parameters: List[Parameter] = Field(..., max_items=16, alias="Parameter")


class AuthOptionsList(BaseModel):
    """
    See section 8.5.2.9 in ISO 15118-2

    The datatype in ISO 15118-2 is called "PaymentOption", but it's rather
    about the authorization method than about payment, thus the name AuthOption
    """

    auth_options: List[AuthEnum] = Field(..., min_items=1, max_items=2, alias="PaymentOption")


class RelativeTimeInterval(BaseModel):
    """See section 8.5.2.18 in ISO 15118-2"""

    start: int = Field(..., ge=0, le=16777214, alias="start")
    duration: int = Field(None, ge=0, le=86400, alias="duration")


class PMaxScheduleEntryDetails(BaseModel):
    """See section 8.5.2.15 in ISO 15118-2"""

    p_max: PVPMax = Field(..., alias="PMax")
    time_interval: RelativeTimeInterval = Field(..., alias="RelativeTimeInterval")


class PMaxScheduleEntry(BaseModel):
    """See section 8.5.2.14 in ISO 15118-2"""

    entry_details: PMaxScheduleEntryDetails = Field(..., alias="PMaxScheduleEntry")


class ResponseCode(str, Enum):
    """See page 271 in ISO 15118-2"""

    OK = "OK"
    OK_NEW_SESSION_ESTABLISHED = "OK_NewSessionEstablished"
    OK_OLD_SESSION_JOINED = "OK_OldSessionJoined"
    OK_CERTIFICATE_EXPIRES_SOON = "OK_CertificateExpiresSoon"
    FAILED = "FAILED"
    FAILED_SEQUENCE_ERROR = "FAILED_SequenceError"
    FAILED_SERVICE_ID_INVALID = "FAILED_ServiceIDInvalid"
    FAILED_UNKNOWN_SESSION = "FAILED_UnknownSession"
    FAILED_SERVICE_SELECTION_INVALID = "FAILED_ServiceSelectionInvalid"
    FAILED_PAYMENT_SELECTION_INVALID = "FAILED_PaymentSelectionInvalid"
    FAILED_CERTIFICATE_EXPIRED = "FAILED_CertificateExpired"
    FAILED_SIGNATURE_ERROR = "FAILED_SignatureError"
    FAILED_NO_CERTIFICATE_AVAILABLE = "FAILED_NoCertificateAvailable"
    FAILED_CERT_CHAIN_ERROR = "FAILED_CertChainError"
    FAILED_CHALLENGE_INVALID = "FAILED_ChallengeInvalid"
    FAILED_CONTRACT_CANCELED = "FAILED_ContractCanceled"
    FAILED_WRONG_CHARGE_PARAMETER = "FAILED_WrongChargeParameter"
    FAILED_POWER_DELIVERY_NOT_APPLIED = "FAILED_PowerDeliveryNotApplied"
    FAILED_TARIFF_SELECTION_INVALID = "FAILED_TariffSelectionInvalid"
    FAILED_CHARGING_PROFILE_INVALID = "FAILED_ChargingProfileInvalid"
    FAILED_METERING_SIGNATURE_NOT_VALID = "FAILED_MeteringSignatureNotValid"
    FAILED_NO_CHARGE_SERVICE_SELECTED = "FAILED_NoChargeServiceSelected"
    FAILED_WRONG_ENERGY_TRANSFER_MODE = "FAILED_WrongEnergyTransferMode"
    FAILED_CONTACTOR_ERROR = "FAILED_ContactorError"
    FAILED_CERTIFICATE_NOT_ALLOWED_AT_THIS_EVSE = (
        "FAILED_CertificateNotAllowedAtThisEVSE"
    )
    FAILED_CERTIFICATE_REVOKED = "FAILED_CertificateRevoked"


class SelectedService(BaseModel):
    """See section 8.5.2.25 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")
    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    # Table 87 says short, Table 106 says unsignedShort. We go with
    # unsignedShort as it makes more sense (no negative values).
    parameter_set_id: int = Field(None, ge=0, le=65535, alias="ParameterSetID")


class SelectedServiceList(BaseModel):
    """See section 8.5.2.24 in ISO 15118-2"""

    selected_service: List[SelectedService] = Field(
        ..., max_items=16, alias="SelectedService"
    )



class ServiceList(BaseModel):
    """See section 8.5.2.2 in ISO 15118-2"""

    services: List[ServiceDetails] = Field(..., max_items=8, alias="Service")


class ServiceParameterList(BaseModel):
    """See section 8.5.2.21 in ISO 15118-2"""

    parameter_set: List[ParameterSet] = Field(..., max_items=255, alias="ParameterSet")


class SalesTariffEntry(BaseModel):
    """See section 8.5.2.17 in ISO 15118-2"""

    # XSD type unsignedByte with value range [0..255]
    e_price_level: int = Field(None, ge=0, le=255, alias="EPriceLevel")
    time_interval: RelativeTimeInterval = Field(..., alias="RelativeTimeInterval")
    consumption_cost: List[ConsumptionCost] = Field(
        None, max_items=3, alias="ConsumptionCost"
    )

    @validator("consumption_cost")
    def at_least_one_cost_indicator(cls, value, values):
        """
        Check that either e_price_level or consumption_cost is used.
        Both cannot be optional.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if not value and not values.get("e_price_level"):
            raise ValueError(
                "At least e_price_level or consumption_cost must "
                "be set, both cannot be optional."
            )
        return value


class SalesTariff(BaseModel):
    """See section 8.5.2.16 in ISO 15118-2"""

    id: str = Field(None, alias="Id")
    # XSD type unsignedByte with value range [0 .. 255]
    # Table 77 says it's both of type SAIDType (which is unsignedByte) and
    # short, so we choose the smaller value range.
    sales_tariff_id: int = Field(..., ge=0, le=255, alias="SalesTariffID")
    sales_tariff_description: str = Field(
        None, max_length=32, alias="SalesTariffDescription"
    )
    # XSD type unsignedByte with value range [0..255]
    num_e_price_levels: int = Field(None, ge=0, le=255, alias="NumEPriceLevels")
    sales_tariff_entry: List[SalesTariffEntry] = Field(
        ..., max_items=102, alias="SalesTariffEntry"
    )

    @validator("sales_tariff_entry")
    def check_num_e_price_levels(cls, value, values):
        """
        If at least one sales_tariff_entry contains an e_price_level entry,
        then num_e_price_levels must be set accordingly to the aggregate
        number of e_price_levels across all sales_tariff_entry elements.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-
        e_price_levels = 0
        for sales_tariff_entry in value:
            if (
                "e_price_level" in sales_tariff_entry
                or sales_tariff_entry.e_price_level
            ):
                e_price_levels += 1

        if e_price_levels > 0 and "num_e_price_levels" not in values:
            raise ValueError(
                f"SalesTariff contains {e_price_levels} "
                "distinct e_price_level entries, but field "
                "'num_e_price_levels' is not provided."
            )

        if e_price_levels != values["num_e_price_levels"]:
            raise ValueError(
                "The amount of distinct e_price_levels "
                f"{e_price_levels} does not match "
                f"num_e_price_levels "
                f"({values['num_e_price_levels']})"
            )
        return value

    @validator("sales_tariff_id")
    def sales_tariff_id_value_range(cls, value):
        """
        Checks whether the sales_tariff_id field of a SalesTariff object
        object is within the value range [1..255].

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if not 1 <= value <= 255:
            raise ValueError(
                f"The value {value} is outside the allowed value "
                f"range [1..255] for SalesTariffID"
            )
        return value

    def __str__(self):
        # The XSD conform element name
        return "SalesTariff"


class SAScheduleTupleEntry(BaseModel):
    """See section 8.5.2.13 in ISO 15118-2"""

    # XSD type unsignedByte with value range [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    p_max_schedule: List[PMaxScheduleEntry] = Field(
        ..., max_items=1024, alias="PMaxSchedule"
    )
    sales_tariff: SalesTariff = Field(None, alias="SalesTariff")


class SAScheduleTuple(BaseModel):
    """See section 8.5.2.13 in ISO 15118-2"""

    tuple: SAScheduleTupleEntry = Field(..., alias="SAScheduleTuple")


class EMAID(BaseModel):
    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: str = Field(None, alias="Id")
    value: str = Field(..., min_length=14, max_length=15, alias="value")

    def __str__(self):
        # The XSD conform element name
        return "eMAID"
