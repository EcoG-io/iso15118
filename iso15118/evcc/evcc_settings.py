import logging
import os
from dataclasses import dataclass
from typing import Optional, Type

import environs

from iso15118.shared.network import validate_nic
from iso15118.shared.settings import SharedSettings

logger = logging.getLogger(__name__)


@dataclass
class Config(SharedSettings):
    ev_config_file_path: str = None

    def load_envs(self, env_path: Optional[str] = None) -> None:
        """
        Tries to load the .env file containing all the project settings.
        If `env_path` is not specified, it will get the .env on the current
        working directory of the project

        Args:
            env_path (str): Absolute path to the location of the .env file
        """
        super().load_env(env_path)

        # validate the NIC selected
        validate_nic(self.iface)

        self.ev_config_file_path = self.env.path(
            "EVCC_CONFIG_PATH",
            default="iso15118/shared/examples/evcc/iso15118_2/evcc_config_eim_ac.json",
        )
        self.env.seal()  # raise all errors at once, if any
        logger.info("EVCC environment settings:")
        self.print_settings()


RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None
