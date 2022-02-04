"""This file is to simulate the charging station responding to ISO15118 messages."""

import asyncio
from typing import Callable, List, Tuple

from asyncio_mqtt import Client
from mqtt_api.mqtt import Mqtt
from mqtt_api.routing import on
from mqtt_api.v1 import response
from mqtt_api.v1.enums import (
    EnergyTransferModeEnum,
    EVSEIsolationStatus,
    EVSEStatusCode,
    MessageName,
)
from mqtt_api.v1.response import (
    CsACBptConnectorService,
    CsACConnectorService,
    CsConnectorParameters,
    CsConnectorServices,
    CsDCBptConnectorService,
    CsDCConnectorService,
    CsEvseParameters,
)

# TODO: these topic names should be added to the mqtt api
CS_JOSEV = "cs/josev"
JOSEV_CS = "josev/cs"


class ConfigurationStartupHandler(Mqtt):
    def __init__(
        self, mqtt_client: Callable[[], Client], topics: List[Tuple[str, int]]
    ):
        super().__init__(mqtt_client, topics, None)

    @on(MessageName.HLC_CHARGING)
    async def on_hlc_charging(self, *args, **kwargs):
        pass

    @on(MessageName.CS_STATUS_AND_LIMITS)
    async def on_cs_status_and_limits(self):
        return response.CsStatusAndLimitsPayload(
            evses=[
                response.EVSEStatusAndLimitsPayload(
                    evse_id="DE*SWT*E123456789",
                    ac=response.ACStatusAndLimits(
                        max_current=response.MaxCurrentByPhase(l1=16, l2=16, l3=16),
                        nominal_voltage=230,
                        rcd_error=False,
                    ),
                    dc=response.DCStatusAndLimits(
                        present_voltage=0,
                        present_current=0,
                        max_current=200,
                        min_current=0.05,
                        max_voltage=200,
                        min_voltage=0,
                        max_power=4000,
                        current_reg_tolerance=10,
                        peak_current_ripple=5,
                        energy_to_be_delivered=2000,
                        isolation_status=EVSEIsolationStatus.VALID,
                        status_code=EVSEStatusCode.EVSE_READY,
                    ),
                )
            ]
        )

    @on(MessageName.CS_PARAMETERS)
    async def on_cs_params(self):
        ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        dc_core = EnergyTransferModeEnum.DC_CORE

        return response.CsParametersPayload(
            sw_version="v1.0.1",
            hw_version="v2.0.0",
            number_of_evses=1,
            parameters=[
                CsEvseParameters(
                    evse_id="DE*SWT*E123456789",
                    connectors=[
                        CsConnectorParameters(
                            id=1,
                            services=CsConnectorServices(
                                ac=CsACConnectorService(
                                    connector_type=ac_three_phase,
                                    control_mode="??",
                                    nominal_voltage=230,
                                    mobility_needs="??",
                                    pricing="??",
                                    free_service=True,
                                ),
                                dc=CsDCConnectorService(
                                    connector_type=dc_core,
                                    control_mode="??",
                                    mobility_needs="??",
                                    pricing="??",
                                ),
                                ac_bpt=CsACBptConnectorService(
                                    connector_type=dc_core,
                                    control_mode="??",
                                    nominal_voltage=230,
                                    mobility_needs="??",
                                    pricing="??",
                                    bpt_channel="unified",
                                    generator_mode="grid_following",
                                    grid_island_detection_mode="active",
                                    free_service=False,
                                ),
                            ),
                        ),
                        CsConnectorParameters(
                            id=2,
                            services=CsConnectorServices(
                                dc=CsDCConnectorService(
                                    connector_type=dc_core,
                                    control_mode="??",
                                    mobility_needs="??",
                                    pricing="??",
                                ),
                                dc_bpt=CsDCBptConnectorService(
                                    connector_type=dc_core,
                                    control_mode="??",
                                    mobility_needs="??",
                                    pricing="??",
                                    bpt_channel="unified",
                                    generator_mode="grid_following",
                                    free_service=False,
                                ),
                            ),
                        ),
                    ],
                    supports_eim=True,
                    network_interface="eth1",
                ),
            ],
        )


hostname = "localhost"
port = 10_003


def create_client() -> Client:
    return Client(hostname, port)


configuration_handler = ConfigurationStartupHandler(
    mqtt_client=lambda: create_client(),
    topics=[(JOSEV_CS, 1)],
)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(configuration_handler.start())
