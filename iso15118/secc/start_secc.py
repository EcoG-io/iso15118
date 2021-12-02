import asyncio
import logging

from iso15118.secc.comm_session_handler import CommunicationSessionHandler

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """
    session_handler = CommunicationSessionHandler()
    await session_handler.start_session_handler()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
