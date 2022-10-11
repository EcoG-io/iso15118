import asyncio
import json
import logging
from enum import Enum

import dacite
from aiofile import async_open

from iso15118.secc import SECCHandler
from iso15118.secc.controller.evse_config import (
    CsParametersPayload,
    CsStatusAndLimitsPayload,
    EVSEConfig,
)
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


async def load_object(path: str, data_class: str):
    try:
        async with async_open(path, "r") as f:
            json_content = await f.read()
            data = json.loads(json_content)
            return dacite.from_dict(
                data_class=data_class,
                data=data,
                config=dacite.Config(cast=[Enum]),
            )
    except Exception as e:
        raise Exception(
            f"Error loading {data_class} from file ({e}). Path used: {path}"
        )


async def get_cs_config_and_limits(cs_config_path: str, cs_limits_path: str):
    logger.info("Getting CS configuration through cs_config file")
    cs_config = await load_object(cs_config_path, CsParametersPayload)
    logger.info("Getting CS limits through cs_limits file")
    cs_limits = await load_object(cs_limits_path, CsStatusAndLimitsPayload)
    return cs_config, cs_limits


async def build_evse_configs(config: Config):
    evses_cs_config, evses_cs_limits = await get_cs_config_and_limits(
        config.cs_config_file_path, config.cs_limits_file_path
    )
    evse_cs_limits = {}
    for evse_limit in evses_cs_limits.evses:
        evse_cs_limits[evse_limit.evse_id] = evse_limit

    evse_configs = {}
    for cs_config in evses_cs_config.parameters:
        try:
            cs_limits = evse_cs_limits[cs_config.evse_id]
        except KeyError:
            raise KeyError(f"CS limits missing for this EVSE: {cs_config.evse_id}")
        evse_config = EVSEConfig(cs_config=cs_config, cs_limits=cs_limits)
        evse_configs[cs_config.network_interface] = evse_config
    return evse_configs


async def build_evse_controllers(config: Config):
    evse_configs = await build_evse_configs(config)
    evse_controllers = {}
    for key, value in evse_configs.items():
        sim_evse_controller = await SimEVSEController.create(evse_config=value)
        evse_controllers[key] = sim_evse_controller
    return evse_controllers


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """
    config = Config()
    config.load_envs()
    evse_controllers = await build_evse_controllers(config)

    await SECCHandler(
        config=config, evse_controllers=evse_controllers, exi_codec=ExificientEXICodec()
    ).start()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
