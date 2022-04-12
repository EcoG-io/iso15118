from enum import Enum
from typing import List, Literal

from pydantic import Field, root_validator

from iso15118.shared.messages import BaseModel
from iso15118.shared.messages.enums import (
    INT_16_MAX,
    INT_16_MIN,
    IsolationLevel,
    UnitSymbol,
)


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
        calculated_value = value * 10**multiplier
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

    """See section 9.5.2.4 in DIN SPEC 70121"""
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


class DCEVChargeParams(BaseModel):
    dc_max_current_limit: PVEVMaxCurrentLimit
    dc_max_power_limit: PVEVMaxPowerLimit
    dc_max_voltage_limit: PVEVMaxVoltageLimit
    dc_energy_capacity: PVEVEnergyCapacity
    dc_target_current: PVEVTargetCurrent
    dc_target_voltage: PVEVTargetVoltage


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


class SelectedService(BaseModel):
    """See section 9.5.2.14 in DIN SPEC 70121"""

    """See section 8.5.2.25 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")
    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    # Table 87 says short, Table 106 says unsignedShort. We go with
    # unsignedShort as it makes more sense (no negative values).
    parameter_set_id: int = Field(None, ge=0, le=65535, alias="ParameterSetID")


class SelectedServiceList(BaseModel):
    """See section 9.5.2.13 in DIN SPEC 70121"""

    """See section 8.5.2.24 in ISO 15118-2"""

    selected_service: List[SelectedService] = Field(
        ..., max_items=16, alias="SelectedService"
    )
