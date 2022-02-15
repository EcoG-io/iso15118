import logging
from typing import Optional
from iso15118.shared.logging import _init_logger
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.secc.comm_session_handler import CommunicationSessionHandler
from iso15118.secc.secc_settings import Config

_init_logger()
logger = logging.getLogger(__name__)


class SECCHandler(CommunicationSessionHandler):
    def __init__(self, exi_codec: IEXICodec, env_path: Optional[str] = None):
        config = Config()
        config.load_envs(env_path)
        CommunicationSessionHandler.__init__(self, config, exi_codec)

    async def start(self):
        try:
            await self.start_session_handler()
        except Exception as exc:
            logger.error(f"SECC terminated: {exc}")
            # Re-raise so the process ends with a non-zero exit code and the
            # watchdog can restart the service
            raise
