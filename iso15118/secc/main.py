import asyncio
import logging
import sys
import yaml

from iso15118.secc import SECCHandler
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)
args = sys.argv


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """

    global args

    try:
        with open(args[1]) as f:
            config_param = yaml.load(f, Loader=yaml.FullLoader)
        print("Loading configuration parameters from " + args[1])
    except:
        with open("conf_default.yaml") as f:
            config_param = yaml.load(f, Loader=yaml.FullLoader)
        print("Loading default configuration parameters")                        

    sim_evse_controller = await SimEVSEController.create(config_param=config_param)
    await SECCHandler(
        exi_codec=ExificientEXICodec(), evse_controller=sim_evse_controller, config_param=config_param
    ).start()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
