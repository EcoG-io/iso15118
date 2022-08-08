import logging.config
import os

import environs

LOGGING_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER_CONF_PATH = os.path.join(LOGGING_DIR, "logging.conf")


# TODO: find a way to inject the log level setting from the evcc_settings or
# secc_settings Config file, instead of getting the log level again from the .env here

WORK_DIR = os.getcwd()
ENV_PATH = WORK_DIR + "/.env"
env = environs.Env(eager=False)
env.read_env(path=ENV_PATH)  # read .env file, if it exists
LOG_LEVEL = env.str("LOG_LEVEL", default="INFO")
env.seal()  # raise all errors at once, if any


def _init_logger():
    logging.config.fileConfig(fname=LOGGER_CONF_PATH, disable_existing_loggers=False)
    logging.getLogger().setLevel(LOG_LEVEL)

    # An extra logging level if required.
    def trace(self, message, *args, **kwargs):
        pass

    level_num = logging.DEBUG - 5
    level_name = "TRACE"
    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), level_name.lower(), trace)
