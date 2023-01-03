import logging
from typing import Optional

from iso15118 import __version__
from iso15118.evcc.comm_session_handler import CommunicationSessionHandler
from iso15118.evcc.controller.interface import EVControllerInterface
from iso15118.evcc.evcc_config import EVCCConfig
from iso15118.evcc.evcc_settings import Config
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.logging import _init_logger

_init_logger()
logger = logging.getLogger(__name__)


class EVCCHandler(CommunicationSessionHandler):
    def __init__(
        self,
        evcc_config: EVCCConfig,
        iface: str,
        exi_codec: IEXICodec,
        ev_controller: EVControllerInterface,
    ):
        CommunicationSessionHandler.__init__(
            self, evcc_config, iface, exi_codec, ev_controller
        )

    async def start(self):
        try:
            logger.info(f"Starting 15118 version: {__version__}")
            await self.start_session_handler()
        except Exception as exc:
            logger.error(f"EVCC terminated: {exc}")
            # Re-raise so the process ends with a non-zero exit code and the
            # watchdog can restart the service
            raise
