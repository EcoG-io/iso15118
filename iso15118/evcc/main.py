import asyncio
import ipaddress
import logging
import sys
from ipaddress import IPv6Address
from typing import Optional

from iso15118.evcc import Config, EVCCHandler
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.evcc_config import load_from_file
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the EVCC (EV Communication Controller)
    """
    logger.debug(f"Args: {sys.argv}")
    config = Config()
    config.load_envs()
    host: Optional[IPv6Address] = None
    port: Optional[int] = None
    is_tls: Optional[bool] = None
    if len(sys.argv) > 1:
        ev_config_file_path = sys.argv[1]
        if ev_config_file_path:
            config.ev_config_file_path = ev_config_file_path
        if len(sys.argv) == 5:
            try:
                host = ipaddress.IPv6Address(sys.argv[2])
                port = int(sys.argv[3])
                if sys.argv[4].lower() == "tls":
                    is_tls = True
                else:
                    is_tls = False
            except Exception as e:
                host = None
                port = None
                is_tls = None
                logger.debug(f"Error building TCP/TLS server params. {e}")
    evcc_config = await load_from_file(config.ev_config_file_path)
    await EVCCHandler(
        evcc_config=evcc_config,
        iface=config.iface,
        exi_codec=ExificientEXICodec(),
        ev_controller=SimEVController(evcc_config),
    ).start(host, port, is_tls)


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("EVCC program terminated manually")


if __name__ == "__main__":
    run()
