import asyncio
import logging
from typing import Optional

from iso15118.secc.comm_session_handler import CommunicationSessionHandler
from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.secc.secc_settings import Config
from iso15118.shared.logging import _init_logger

_init_logger()
logger = logging.getLogger(__name__)


async def main(
    env_path: Optional[str] = None,
    evse_controller: Optional[EVSEControllerInterface] = None,
):
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """
    try:
        # get configuration
        config = Config()
        await config.load_envs(env_path)
        if config.simulated_secc == True:
            evse_controller_instance = await config.evse_controller.create(config.mqtt_host, config.mqtt_port)
        else:
            evse_controller_instance = await evse_controller.create(config.mqtt_host, config.mqtt_port)
        session_handler = CommunicationSessionHandler(config, evse_controller_instance)
        await session_handler.start_session_handler()
    except Exception as exc:
        logger.error(f"SECC terminated: {exc}")
        # Re-raise so the process ends with a non-zero exit code and the
        # watchdog can restart the service
        raise


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
