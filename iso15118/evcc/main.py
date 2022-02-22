import asyncio
import logging

from iso15118.evcc import EVCCHandler
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the EVCC (EV Communication Controller)
    """
    await EVCCHandler(
        exi_codec=ExificientEXICodec(), ev_controller=SimEVController()
    ).start()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("EVCC program terminated manually")


if __name__ == "__main__":
    run()
