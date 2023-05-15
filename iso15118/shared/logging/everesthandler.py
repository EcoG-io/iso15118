from logging import Handler, LogRecord
from logging import (
    CRITICAL,
    ERROR,
    WARNING
)
from everestpy import log

class EverestHandler(Handler):

    def __init__(self):
        Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)

        log_level: int  = record.levelno
        if log_level == CRITICAL:
            log.critical(msg)
        elif log_level == ERROR:
            log.error(msg)
        elif log_level == WARNING:
            log.warning(msg)
        else:
            log.debug(msg)
