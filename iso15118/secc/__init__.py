import logging
from typing import Optional

from iso15118 import __version__
from iso15118.secc.comm_session_handler import CommunicationSessionHandler
from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.secc.secc_settings import Config
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.logging import _init_logger

_init_logger()
logger = logging.getLogger(__name__)


class SECCHandler(CommunicationSessionHandler):
    def __init__(
        self,
        exi_codec: IEXICodec,
        evse_controller: EVSEControllerInterface,
        config: Config,
    ):
        CommunicationSessionHandler.__init__(
            self,
            config,
            exi_codec,
            evse_controller,
        )

    async def start(self, iface: str, start_udp_server: Optional[bool] = True):
        try:
            logger.info(f"Starting 15118 version: {__version__}")
            await self.start_session_handler(iface, start_udp_server)
        except Exception as exc:
            logger.error(f"SECC terminated: {exc}")
            # Re-raise so the process ends with a non-zero exit code and the
            # watchdog can restart the service
            raise
