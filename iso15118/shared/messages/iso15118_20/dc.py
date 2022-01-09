"""
This modules contains classes which implement all the elements of the
ISO 15118-20 XSD file V2G_CI_DC.xsd (see folder 'schemas').
These are the V2GMessages exchanged between the EVCC and the SECC specifically
for DC charging.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.
"""

from pydantic import Field, root_validator

from iso15118.shared.messages import BaseModel
from iso15118.shared.messages.iso15118_20.common_types import (
    ChargeLoopReq,
    ChargeLoopRes,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
    DynamicChargeLoopReqParams,
    DynamicChargeLoopResParams,
    RationalNumber,
    ScheduledChargeLoopReqParams,
    ScheduledChargeLoopResParams,
)
from iso15118.shared.validators import one_field_must_be_set


class DCChargeParameterDiscoveryReqParams(BaseModel):
    """See section 8.3.5.4.1 in ISO 15118-20"""

    ev_max_charge_power: RationalNumber = Field(..., alias="EVMaximumChargePower")
    ev_min_charge_power: RationalNumber = Field(..., alias="EVMinimumChargePower")
    ev_max_charge_current: RationalNumber = Field(..., alias="EVMaximumChargeCurrent")
    ev_min_charge_current: RationalNumber = Field(..., alias="EVMinimumChargeCurrent")
    ev_max_voltage: RationalNumber = Field(..., alias="EVMaximumVoltage")
    ev_min_voltage: RationalNumber = Field(..., alias="EVMinimumVoltage")
    target_soc: int = Field(None, ge=0, le=100, alias="TargetSOC")


class DCChargeParameterDiscoveryResParams(BaseModel):
    """See section 8.3.5.4.2 in ISO 15118-20"""

    evse_max_charge_power: RationalNumber = Field(..., alias="EVSEMaximumChargePower")
    evse_min_charge_power: RationalNumber = Field(..., alias="EVSEMinimumChargePower")
    evse_max_charge_current: RationalNumber = Field(
        ..., alias="EVSEMaximumChargeCurrent"
    )
    evse_min_charge_current: RationalNumber = Field(
        ..., alias="EVSEMinimumChargeCurrent"
    )
    evse_max_voltage: RationalNumber = Field(..., alias="EVSEMaximumVoltage")
    evse_min_voltage: RationalNumber = Field(..., alias="EVSEMinimumVoltage")
    evse_power_ramp_limit: RationalNumber = Field(None, alias="EVSEPowerRampLimitation")


class BPTDCChargeParameterDiscoveryReqParams(DCChargeParameterDiscoveryReqParams):
    """
    See section 8.3.5.4.7.1 in ISO 15118-20
    BPT = Bidirectional Power Transfer
    """

    ev_max_discharge_power: RationalNumber = Field(..., alias="EVMaximumDischargePower")
    ev_min_discharge_power: RationalNumber = Field(..., alias="EVMinimumDischargePower")
    ev_max_discharge_current: RationalNumber = Field(
        ..., alias="EVMaximumDischargeCurrent"
    )
    ev_min_discharge_current: RationalNumber = Field(
        ..., alias="EVMinimumDischargeCurrent"
    )


class BPTDCChargeParameterDiscoveryResParams(DCChargeParameterDiscoveryResParams):
    """
    See section 8.3.5.4.7.2 in ISO 15118-20
    BPT = Bidirectional Power Transfer
    """

    evse_max_discharge_power: RationalNumber = Field(
        ..., alias="EVSEMaximumDischargePower"
    )
    evse_min_discharge_power: RationalNumber = Field(
        ..., alias="EVSEMinimumDischargePower"
    )
    evse_max_discharge_current: RationalNumber = Field(
        ..., alias="EVSEMaximumDischargeCurrent"
    )
    evse_min_discharge_current: RationalNumber = Field(
        ..., alias="EVSEMinimumDischargeCurrent"
    )


class ScheduledDCChargeLoopReqParams(ScheduledChargeLoopReqParams):
    """See section 8.3.5.4.4 in ISO 15118-20"""

    ev_max_charge_power: RationalNumber = Field(None, alias="EVMaximumChargePower")
    ev_max_charge_power_l2: RationalNumber = Field(
        None, alias="EVMaximumChargePower_L2"
    )
    ev_max_charge_power_l3: RationalNumber = Field(
        None, alias="EVMaximumChargePower_L3"
    )
    ev_min_charge_power: RationalNumber = Field(None, alias="EVMinimumChargePower")
    ev_min_charge_power_l2: RationalNumber = Field(
        None, alias="EVMinimumChargePower_L2"
    )
    ev_min_charge_power_l3: RationalNumber = Field(
        None, alias="EVMinimumChargePower_L3"
    )
    ev_present_active_power: RationalNumber = Field(..., alias="EVPresentActivePower")
    ev_present_active_power_l2: RationalNumber = Field(
        None, alias="EVPresentActivePower_L2"
    )
    ev_present_active_power_l3: RationalNumber = Field(
        None, alias="EVPresentActivePower_L3"
    )
    ev_present_reactive_power: RationalNumber = Field(
        None, alias="EVPresentReactivePower"
    )
    ev_present_reactive_power_l2: RationalNumber = Field(
        None, alias="EVPresentReactivePower_L2"
    )
    ev_present_reactive_power_l3: RationalNumber = Field(
        None, alias="EVPresentReactivePower_L3"
    )


class ScheduledDCChargeLoopResParams(ScheduledChargeLoopResParams):
    """See section 8.3.5.4.6 in ISO 15118-20"""

    evse_target_active_power: RationalNumber = Field(
        None, alias="EVSETargetActivePower"
    )
    evse_target_active_power_l2: RationalNumber = Field(
        None, alias="EVSETargetActivePower_L2"
    )
    evse_target_active_power_l3: RationalNumber = Field(
        None, alias="EVSETargetActivePower_L3"
    )
    evse_target_reactive_power: RationalNumber = Field(
        None, alias="EVSETargetReactivePower"
    )
    evse_target_reactive_power_l2: RationalNumber = Field(
        None, alias="EVSETargetReactivePower_L2"
    )
    evse_target_reactive_power_l3: RationalNumber = Field(
        None, alias="EVSETargetReactivePower_L3"
    )
    evse_present_active_power: RationalNumber = Field(
        None, alias="EVSEPresentActivePower"
    )
    evse_present_active_power_l2: RationalNumber = Field(
        None, alias="EVSEPresentActivePower_L2"
    )
    evse_present_active_power_l3: RationalNumber = Field(
        None, alias="EVSEPresentActivePower_L3"
    )


class BPTScheduledDCChargeLoopReqParams(ScheduledDCChargeLoopReqParams):
    """See section 8.3.5.4.7.4 in ISO 15118-20"""

    ev_max_discharge_power: RationalNumber = Field(
        None, alias="EVMaximumDischargePower"
    )
    ev_max_discharge_power_l2: RationalNumber = Field(
        None, alias="EVMaximumDischargePower_L2"
    )
    ev_max_discharge_power_l3: RationalNumber = Field(
        None, alias="EVMaximumDischargePower_L3"
    )
    ev_min_discharge_power: RationalNumber = Field(
        None, alias="EVMinimumDischargePower"
    )
    ev_min_discharge_power_l2: RationalNumber = Field(
        None, alias="EVMinimumDischargePower_L2"
    )
    ev_min_discharge_power_l3: RationalNumber = Field(
        None, alias="EVMinimumDischargePower_L3"
    )


class BPTScheduledDCChargeLoopResParams(ScheduledDCChargeLoopResParams):
    """See section 8.3.5.4.7.6 in ISO 15118-20"""


class DynamicDCChargeLoopReq(DynamicChargeLoopReqParams):
    """See section 8.3.5.4.3 in ISO 15118-20"""

    ev_max_charge_power: RationalNumber = Field(..., alias="EVMaximumChargePower")
    ev_max_charge_power_l2: RationalNumber = Field(
        None, alias="EVMaximumChargePower_L2"
    )
    ev_max_charge_power_l3: RationalNumber = Field(
        None, alias="EVMaximumChargePower_l2"
    )
    ev_min_charge_power: RationalNumber = Field(..., alias="EVMinimumChargePower")
    ev_min_charge_power_l2: RationalNumber = Field(
        None, alias="EVMinimumChargePower_L2"
    )
    ev_min_charge_power_l3: RationalNumber = Field(
        None, alias="EVMinimumChargePower_L3"
    )
    ev_present_active_power: RationalNumber = Field(..., alias="EVPresentActivePower")
    ev_present_active_power_l2: RationalNumber = Field(
        None, alias="EVPresentActivePower_L2"
    )
    ev_present_active_power_l3: RationalNumber = Field(
        None, alias="EVPresentActivePower_L3"
    )
    ev_present_reactive_power: RationalNumber = Field(
        ..., alias="EVPresentReactivePower"
    )
    ev_present_reactive_power_l2: RationalNumber = Field(
        None, alias="EVPresentReactivePower_L2"
    )
    ev_present_reactive_power_l3: RationalNumber = Field(
        None, alias="EVPresentReactivePower_L3"
    )


class DynamicDCChargeLoopRes(DynamicChargeLoopResParams):
    """See section 8.3.5.4.5 in ISO 15118-20"""

    evse_target_active_power: RationalNumber = Field(..., alias="EVSETargetActivePower")
    evse_target_active_power_l2: RationalNumber = Field(
        None, alias="EVSETargetActivePower_L2"
    )
    evse_target_active_power_l3: RationalNumber = Field(
        None, alias="EVSETargetActivePower_L3"
    )
    evse_target_reactive_power: RationalNumber = Field(
        None, alias="EVSETargetReactivePower"
    )
    evse_target_reactive_power_l2: RationalNumber = Field(
        None, alias="EVSETargetReactivePower_L2"
    )
    evse_target_reactive_power_l3: RationalNumber = Field(
        None, alias="EVSETargetReactivePower_L3"
    )
    evse_present_active_power: RationalNumber = Field(
        None, alias="EVSEPresentActivePower"
    )
    evse_present_active_power_l2: RationalNumber = Field(
        None, alias="EVSEPresentActivePower_L2"
    )
    evse_present_active_power_l3: RationalNumber = Field(
        None, alias="EVSEPresentActivePower_L3"
    )


class BPTDynamicDCChargeLoopReq(DynamicDCChargeLoopReq):
    """See section 8.3.5.4.7.3 in ISO 15118-20"""

    ev_max_discharge_power: RationalNumber = Field(..., alias="EVMaximumDischargePower")
    ev_max_discharge_power_l2: RationalNumber = Field(
        None, alias="EVMaximumDischargePower_L2"
    )
    ev_max_discharge_power_l3: RationalNumber = Field(
        None, alias="EVMaximumDischargePower_L3"
    )
    ev_min_discharge_power: RationalNumber = Field(..., alias="EVMinimumDischargePower")
    ev_min_discharge_power_l2: RationalNumber = Field(
        None, alias="EVMinimumDischargePower_L2"
    )
    ev_min_discharge_power_l3: RationalNumber = Field(
        None, alias="EVMinimumDischargePower_L3"
    )
    ev_max_v2x_energy_request: RationalNumber = Field(
        None, alias="EVMaximumV2XEnergyRequest"
    )
    ev_min_v2x_energy_request: RationalNumber = Field(
        None, alias="EVMinimumV2XEnergyRequest"
    )


class BPTDynamicDCChargeLoopRes(DynamicDCChargeLoopRes):
    """See section 8.3.5.4.7.5 in ISO 15118-20"""


class DCChargeParameterDiscoveryReq(ChargeParameterDiscoveryReq):
    """See section 8.3.4.4.2.2 in ISO 15118-20"""

    dc_params: DCChargeParameterDiscoveryReqParams = Field(
        None, alias="DC_CPDReqEnergyTransferMode"
    )
    bpt_dc_params: BPTDCChargeParameterDiscoveryReqParams = Field(
        None, alias="BPT_DC_CPDReqEnergyTransferMode"
    )

    @root_validator(pre=True)
    def either_dc_or_dc_bpt_params(cls, values):
        """
        Either dc_params or bpt_dc_params must be set, depending on whether
        unidirectional or bidirectional power transfer was chosen.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "dc_params",
                "DC_CPDReqEnergyTransferMode",
                "bpt_dc_params",
                "BPT_DC_CPDReqEnergyTransferMode",
            ],
            values,
            True,
        ):
            return values

    def __str__(self):
        # The XSD-conform name
        return "DC_ChargeParameterDiscoveryReq"


class DCChargeParameterDiscoveryRes(ChargeParameterDiscoveryRes):
    """See section 8.3.4.4.2.3 in ISO 15118-20"""

    dc_params: DCChargeParameterDiscoveryResParams = Field(
        None, alias="DC_CPDResEnergyTransferMode"
    )
    bpt_dc_params: BPTDCChargeParameterDiscoveryResParams = Field(
        None, alias="BPT_DC_CPDResEnergyTransferMode"
    )

    @root_validator(pre=True)
    def either_dc_or_bpt_dc_params(cls, values):
        """
        Either dc_params or bpt_dc_params must be set, depending on whether
        unidirectional or bidirectional power transfer was chosen.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "dc_params",
                "DC_CPDResEnergyTransferMode",
                "bpt_dc_params",
                "BPT_DC_CPDResEnergyTransferMode",
            ],
            values,
            True,
        ):
            return values

    def __str__(self):
        # The XSD-conform name
        return "DC_ChargeParameterDiscoveryRes"


class DCChargeLoopReq(ChargeLoopReq):
    """See section 8.3.4.4.3.2 in ISO 15118-20"""

    scheduled_params: ScheduledDCChargeLoopReqParams = Field(
        None, alias="Scheduled_DC_CLReqControlMode"
    )
    dynamic_params: DynamicDCChargeLoopReq = Field(
        None, alias="Dynamic_DC_CLReqControlMode"
    )
    bpt_scheduled_params: BPTScheduledDCChargeLoopReqParams = Field(
        None, alias="BPT_Scheduled_DC_CLReqControlMode"
    )
    bpt_dynamic_params: BPTDynamicDCChargeLoopReq = Field(
        None, alias="BPT_Dynamic_DC_CLReqControlMode"
    )

    @root_validator(pre=True)
    def either_scheduled_or_dynamic_bpt(cls, values):
        """
        Either scheduled_params or dynamic_params or bpt_scheduled_params or
        bpt_dynamic_params must be set, depending on whether unidirectional or
        bidirectional power transfer and whether scheduled or dynamic mode was chosen.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "scheduled_params",
                "Scheduled_DC_CLReqControlMode",
                "dynamic_params",
                "Dynamic_DC_CLReqControlMode",
                "bpt_scheduled_params",
                "BPT_Scheduled_DC_CLReqControlMode",
                "bpt_dynamic_params",
                "BPT_Dynamic_DC_CLReqControlMode",
            ],
            values,
            True,
        ):
            return values

    def __str__(self):
        # The XSD-conform name
        return "DC_ChargeLoopReq"


class DCChargeLoopRes(ChargeLoopRes):
    """See section 8.3.4.4.3.3 in ISO 15118-20"""

    evse_target_frequency: RationalNumber = Field(None, alias="EVSETargetFrequency")
    scheduled_dc_charge_loop_res: ScheduledDCChargeLoopResParams = Field(
        None, alias="Scheduled_DC_CLResControlMode"
    )
    dynamic_dc_charge_loop_res: DynamicDCChargeLoopRes = Field(
        None, alias="Dynamic_DC_CLResControlMode"
    )
    bpt_scheduled_dc_charge_loop_res: BPTScheduledDCChargeLoopResParams = Field(
        None, alias="BPT_Scheduled_DC_CLResControlMode"
    )
    bpt_dynamic_dc_charge_loop_res: BPTDynamicDCChargeLoopRes = Field(
        None, alias="BPT_Dynamic_DC_CLResControlMode"
    )

    @root_validator(pre=True)
    def either_scheduled_or_dynamic_bpt(cls, values):
        """
        Either scheduled_dc_charge_loop_res or scheduled_dc_charge_loop_res or
        bpt_scheduled_dc_charge_loop_res or bpt_dynamic_dc_charge_loop_res
        must be set, depending on whether unidirectional or bidirectional power
        transfer and whether scheduled or dynamic mode was chosen.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "scheduled_dc_charge_loop_res",
                "Scheduled_DC_CLResControlMode",
                "dynamic_dc_charge_loop_res",
                "Dynamic_DC_CLResControlMode",
                "bpt_scheduled_dc_charge_loop_res",
                "BPT_Scheduled_DC_CLResControlMode",
                "bpt_dynamic_dc_charge_loop_res",
                "BPT_Dynamic_DC_CLResControlMode",
            ],
            values,
            True,
        ):
            return values

    def __str__(self):
        # The XSD-conform name
        return "DC_ChargeLoopRes"


class DCCableCheckReq(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_CableCheckReq"


class DCCableCheckRes(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_CableCheckRes"


class DCPreChargeReq(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_PreChargeReq"


class DCPreChargeRes(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_PreChargeRes"


class DCWeldingDetectionReq(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_WeldingDetectionReq"


class DCWeldingDetectionRes(BaseModel):
    def __str__(self):
        # The XSD-conform name
        return "DC_WeldingDetectionRes"
