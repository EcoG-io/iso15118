import asyncio
import logging

from iso15118.secc import SECCHandler
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


async def main(env_path: Optional[str] = None):
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """
    # if no EVSEController implementation is passed to the constructor of SECCHandler,
    # then SimEVSEController will be used.

    config = Config()
    config.load_envs(env_path)
    evse_controller = await SimEVSEController().create()
    await SECCHandler(
        config=config, exi_codec=ExificientEXICodec(), evse_controller=evse_controller
    ).start()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()