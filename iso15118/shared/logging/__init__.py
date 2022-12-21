import logging.config

from iso15118.shared.logging.everesthandler import EverestHandler

# TODO: find a way to inject the log level setting from the evcc_settings or
# secc_settings Config file, instead of getting the log level again from the .env here

LOG_LEVEL = "INFO"

def _init_logger():
    eh = EverestHandler()
    formatter = logging.Formatter("%(levelname)s - %(name)s (%(lineno)d): %(message)s")
    eh.setFormatter(formatter)
    
    logging.getLogger().addHandler(eh)
    logging.getLogger().setLevel(LOG_LEVEL)

    # An extra logging level if required.
    def trace(self, message, *args, **kwargs):
        pass

    level_num = logging.DEBUG - 5
    level_name = "TRACE"
    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), level_name.lower(), trace)
