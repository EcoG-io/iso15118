import logging.config
import os

LOGGING_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER_CONF_PATH = os.path.join(LOGGING_DIR, "logging.conf")


def _init_logger():
    logging.config.fileConfig(fname=LOGGER_CONF_PATH, disable_existing_loggers=False)
