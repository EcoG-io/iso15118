import dataclasses
import logging
import os
from abc import ABC
from typing import Optional

import environs

from iso15118.shared.network import validate_nic

SHARED_CWD = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger(__name__)

JAR_FILE_PATH = SHARED_CWD + "/EXICodec.jar"
DEFAULT_PKI_PATH = SHARED_CWD + "/pki/"
DEFAULT_V20_EVSE_SERVICE_CONFIG = (
    SHARED_CWD + "/examples/secc/15118_20/service_config.json"
)


@dataclasses.dataclass
class SharedSettings(ABC):
    env = environs.Env(eager=False)
    pki_path: Optional[str] = DEFAULT_PKI_PATH
    message_log_json: bool = True
    message_log_exi: Optional[str] = None
    v20_evse_service_config: Optional[str] = DEFAULT_V20_EVSE_SERVICE_CONFIG
    enable_tls_1_3: bool = False
    iface: Optional[str] = None
    log_level: Optional[int] = None

    def load_env(self, env_path: Optional[str] = None):
        if not env_path:
            work_dir = os.getcwd()
            env_path = work_dir + "/.env"
        self.env.read_env(path=env_path)  # read .env file, if it exists
        self.log_level = self.env.str("LOG_LEVEL", default="INFO")
        self.iface = self.env.str("NETWORK_INTERFACE", default="eth0")
        # validate the NIC selected
        validate_nic(self.iface)

        self.pki_path = self.env.path("PKI_PATH", default=DEFAULT_PKI_PATH)

        self.message_log_json = self.env.bool("MESSAGE_LOG_JSON", default=True)
        self.message_log_exi = self.env.bool("MESSAGE_LOG_EXI", default=False)

        self.v20_evse_service_config = self.env.str(
            "V20_SERVICE_CONFIG",
            default=DEFAULT_V20_EVSE_SERVICE_CONFIG,
        )

        self.enable_tls_1_3 = self.env.bool("ENABLE_TLS_1_3", default=False)

    def print_settings(self):
        for key, value in self.env.dump().items():
            logger.info(f"{key:30}: {value}")

    def update(self, new: dict):
        self.as_dict().update(new)

    def as_dict(self):
        return self.__dict__
