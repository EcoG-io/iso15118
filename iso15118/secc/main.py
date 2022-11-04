import asyncio
import logging

from iso15118.secc import SECCHandler
from iso15118.secc.controller.evse_config import build_evse_configs
from iso15118.secc.controller.interface import ServiceStatus
from iso15118.secc.controller.simulator import ISO15118ServiceManager, SimEVSEController
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


async def build_evse_controllers(cs_config_path: str, cs_limits_path: str):
    evse_configs = await build_evse_configs(
        cs_config_path=cs_config_path, cs_limits_path=cs_limits_path
    )
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
    evse_controllers = await build_evse_controllers(
        config.cs_config_file_path, config.cs_limits_file_path
    )
    monitor = ISO15118ServiceManager()
    monitor.set_status(ServiceStatus.STARTING)
    await SECCHandler(
        config=config,
        evse_controllers=evse_controllers,
        exi_codec=ExificientEXICodec(),
        service_monitor=monitor,
    ).start()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
