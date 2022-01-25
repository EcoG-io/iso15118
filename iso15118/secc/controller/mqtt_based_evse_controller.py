import asyncio
from dataclasses import asdict
from typing import List, Optional, Union

from asyncio_mqtt import Client
from mqtt_api.mqtt import Mqtt
from mqtt_api.v1 import request, response
from mqtt_api.v1.enums import Topics

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EnergyTransferModeEnum,
    EVSENotification,
    IsolationLevel,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PVEVSECurrentRegulationTolerance,
    PVEVSEEnergyToBeDelivered,
    PVEVSEMaxCurrent,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSENominalVoltage,
    PVEVSEPeakCurrentRipple,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    SAScheduleTupleEntry,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20


class MQTTBasedEVSEController(EVSEControllerInterface):
    @staticmethod
    def _build_mqtt(hostname: str, port: int) -> Mqtt:
        def create_client() -> Client:
            mqtt_client = Client(hostname, port)
            return mqtt_client

        return Mqtt(
            mqtt_client=lambda: create_client(),
            topics=Topics.CS_ISO15118,
            translator=None,
            response_timeout=60,
        )

    @classmethod
    async def create(cls, mqtt_host: str, mqtt_port: int) -> "MQTTBasedEVSEController":
        """Get cs_parameters and cs_status_and_limits from MQTT"""
        mqtt_service = cls._build_mqtt(mqtt_host, mqtt_port)
        mqtt_service_task = asyncio.create_task(mqtt_service.start())
        cs_parameters: response.CsParametersPayload = await mqtt_service.request(
            topic=Topics.ISO15118_CS, payload=request.CsParametersPayload()
        )
        if cs_parameters.number_of_evses != 1 or len(cs_parameters.parameters) != 1:
            raise AttributeError(
                "Only single EVSE configurations are currently supported."
            )

        cs_status_and_limits: response.CsStatusAndLimitsPayload = (
            await mqtt_service.request(
                topic=Topics.ISO15118_CS, payload=request.CsStatusAndLimitsPayload()
            )
        )

        if len(cs_status_and_limits.evses) != 1:
            raise AttributeError(
                "Only single EVSE configurations are currently supported"
            )

        status_limits_evse_id = cs_status_and_limits.evses[0].evse_id
        cs_param_evse_id = cs_parameters.parameters[0].evse_id
        if status_limits_evse_id != cs_param_evse_id:
            raise AttributeError(
                f"cs_parameters (evse id: {cs_param_evse_id}) and "
                f"cs_status_and_limits (evse_id: {status_limits_evse_id}) "
                f"should have the same evse_id."
            )

        mqtt_service_task.cancel("MQTT setup completed.")

        return MQTTBasedEVSEController(cs_parameters, cs_status_and_limits)

    def __init__(
        self,
        cs_parameters: response.CsParametersPayload,
        cs_status_and_limits: response.CsStatusAndLimitsPayload,
    ) -> None:
        self.cs_parameters = cs_parameters
        self.cs_status_and_limits = cs_status_and_limits
        # to be used in places where MQTT has not been
        # wired in yet.
        self.simulated_controller = SimEVSEController()

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    def get_evse_id(self) -> str:
        return self.cs_parameters.parameters[0].evse_id

    def get_supported_energy_transfer_modes(self) -> List[EnergyTransferModeEnum]:
        transfer_modes = set()

        connectors = self.cs_parameters.parameters[0].connectors
        for connector in connectors:
            if ac := connector.services.ac:
                if ac.connector == "three_phase":
                    transfer_modes.add(EnergyTransferModeEnum.AC_THREE_PHASE_CORE)
                if ac.connector == "core":
                    transfer_modes.add(EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE)

            if dc := connector.services.dc:
                if dc.connector == "core":
                    transfer_modes.add(EnergyTransferModeEnum.DC_CORE)
                if dc.connector == "extended":
                    transfer_modes.add(EnergyTransferModeEnum.DC_EXTENDED)
                if dc.connector == "unique":
                    transfer_modes.add(EnergyTransferModeEnum.DC_UNIQUE)
                if dc.connector == "combo_core":
                    transfer_modes.add(EnergyTransferModeEnum.DC_COMBO_CORE)

        return list(transfer_modes)

    def is_authorised(self) -> bool:
        return True

    def get_sa_schedule_list(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntry]]:
        return self.simulated_controller.get_sa_schedule_list(
            max_schedule_entries, departure_time
        )

    def get_meter_info(self, protocol: Protocol) -> Union[MeterInfoV2, MeterInfoV20]:
        return self.simulated_controller.get_meter_info(protocol)

    def get_supported_providers(self) -> Optional[List[ProviderID]]:
        return self.simulated_controller.get_supported_providers()

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_ac_evse_status(self) -> ACEVSEStatus:
        rcd_error = self.cs_status_and_limits.evses[0].ac.rcd_error
        return ACEVSEStatus(
            rcd=rcd_error,
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
        )

    def get_ac_evse_charge_parameter(self) -> ACEVSEChargeParameter:
        nominal_voltage_value = self.cs_status_and_limits.evses[0].ac.nominal_voltage
        nominal_voltage = PVEVSENominalVoltage(
            multiplier=0, value=nominal_voltage_value, unit=UnitSymbol.VOLTAGE
        )

        smallest_max_current = min(
            asdict(self.cs_status_and_limits.evses[0].ac.max_current).values()
        )
        max_current = PVEVSEMaxCurrent(
            multiplier=0, value=smallest_max_current, unit=UnitSymbol.AMPERE
        )

        return ACEVSEChargeParameter(
            ac_evse_status=self.get_ac_evse_status(),
            evse_nominal_voltage=nominal_voltage,
            evse_max_current=max_current,
        )

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_dc_evse_status(self) -> DCEVSEStatus:
        isolation_status = self.cs_status_and_limits.evses[0].dc.isolation_status

        # map the MQTT API enums to the ISO 15118 ones
        if isolation_status and isolation_status.name in IsolationLevel.__members__:
            isolation_level = IsolationLevel[isolation_status.name]
        else:
            isolation_level = None

        # TODO: the evse status code should be added
        #  as an enum to the MQTT API and Gitbook.
        evse_status = self.cs_status_and_limits.evses[0].dc.status_code
        if evse_status == "ready":
            status_code = DCEVSEStatusCode.EVSE_READY
        else:
            status_code = DCEVSEStatusCode.EVSE_NOT_READY

        return DCEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
            evse_isolation_status=isolation_level,
            evse_status_code=status_code,
        )

    def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        dc_limits = self.cs_status_and_limits.evses[0].dc

        if not dc_limits:
            raise AttributeError("dc limits are not available.")

        evse_maximum_power_limit = PVEVSEMaxPowerLimit(
            value=dc_limits.max_power,
            multiplier=0,
            unit=UnitSymbol.WATT,
        )

        evse_minimum_current_limit = PVEVSEMinCurrentLimit(
            value=int(dc_limits.min_current),
            multiplier=0,
            unit=UnitSymbol.AMPERE,
        )

        evse_maximum_current_limit = PVEVSEMaxCurrentLimit(
            value=dc_limits.max_current,
            multiplier=0,
            unit=UnitSymbol.AMPERE,
        )

        evse_minimum_voltage_limit = PVEVSEMinVoltageLimit(
            value=dc_limits.min_voltage,
            multiplier=0,
            unit=UnitSymbol.VOLTAGE,
        )

        evse_maximum_voltage_limit = PVEVSEMaxVoltageLimit(
            value=dc_limits.max_voltage,
            multiplier=0,
            unit=UnitSymbol.VOLTAGE,
        )

        evse_current_regulation_tolerance = PVEVSECurrentRegulationTolerance(
            value=dc_limits.current_reg_tolerance,
            multiplier=0,
            unit=UnitSymbol.AMPERE,
        )

        evse_peak_current_ripple = PVEVSEPeakCurrentRipple(
            value=dc_limits.peak_current_ripple,
            multiplier=0,
            unit=UnitSymbol.AMPERE,
        )

        evse_energy_to_be_delivered = PVEVSEEnergyToBeDelivered(
            value=dc_limits.energy_to_be_delivered,
            multiplier=0,
            unit=UnitSymbol.WATT,
        )

        return DCEVSEChargeParameter(
            dc_evse_status=self.get_dc_evse_status(),
            evse_maximum_power_limit=evse_maximum_power_limit,
            evse_minimum_current_limit=evse_minimum_current_limit,
            evse_maximum_current_limit=evse_maximum_current_limit,
            evse_minimum_voltage_limit=evse_minimum_voltage_limit,
            evse_maximum_voltage_limit=evse_maximum_voltage_limit,
            evse_current_regulation_tolerance=evse_current_regulation_tolerance,
            evse_peak_current_ripple=evse_peak_current_ripple,
            evse_energy_to_be_delivered=evse_energy_to_be_delivered,
        )

    def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        return self.simulated_controller.get_evse_present_voltage()

    def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        return self.simulated_controller.get_evse_present_current()
