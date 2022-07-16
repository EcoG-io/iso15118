import logging
import os
from dataclasses import dataclass
from typing import List, Optional, Type

import environs

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.exceptions import (
    NoSupportedAuthenticationModes,
    NoSupportedProtocols,
)
from iso15118.shared.messages.enums import AuthEnum, Protocol

logger = logging.getLogger(__name__)


def format_list(read_settings: List[str]) -> List[str]:
    read_settings = list(filter(None, read_settings))
    read_settings = [setting.strip().upper() for setting in read_settings]
    read_settings = list(set(read_settings))
    return read_settings


@dataclass
class Config:
    iface: Optional[str] = None
    log_level: Optional[int] = None
    evse_controller: Type[EVSEControllerInterface] = None
    enforce_tls: bool = False
    free_charging_service: bool = False
    free_cert_install_service: bool = True
    allow_cert_install_service: bool = True
    use_cpo_backend: bool = False
    supported_protocols: Optional[List[Protocol]] = None
    supported_auth_options: Optional[List[AuthEnum]] = None
    standby_allowed: bool = False
    default_protocols = [
        "DIN_SPEC_70121",
        "ISO_15118_2",
        "ISO_15118_20_AC",
        "ISO_15118_20_DC",
    ]
    # NOTE: ISO 15118 DC support is still under development
    default_auth_modes = [
        "EIM",
        "PNC",
    ]

    def load_envs(self, env_path: Optional[str] = None) -> None:
        """
        Tries to load the .env file containing all the project settings.
        If `env_path` is not specified, it will get the .env on the current
        working directory of the project
        Args:
            env_path (str): Absolute path to the location of the .env file
        """
        env = environs.Env(eager=False)
        if not env_path:
            env_path = os.getcwd() + "/.env"
        env.read_env(path=env_path)  # read .env file, if it exists

        self.iface = env.str("NETWORK_INTERFACE", default="eth0")

        self.log_level = env.str("LOG_LEVEL", default="INFO")

        # Indicates whether or not the SECC should always enforce a TLS-secured
        # communication session. If True, the SECC will only fire up a TCP server
        # with an SSL session context and ignore the Security byte value from the
        # SDP request.
        self.enforce_tls = env.bool("SECC_ENFORCE_TLS", default=False)

        # Indicates whether or not the ChargeService (energy transfer) is free.
        # Should be configurable via OCPP messages.
        # Must be one of the bool values True or False
        self.free_charging_service = env.bool("FREE_CHARGING_SERVICE", default=False)

        # Indicates whether or not the installation of a contract certificate is free.
        # Should be configurable via OCPP messages.
        # Must be one of the bool values True or False
        self.free_cert_install_service = env.bool(
            "FREE_CERT_INSTALL_SERVICE", default=True
        )

        # Indicates if CPO integration is available to perform contract
        # certificate installation.
        self.use_cpo_backend = env.bool("USE_CPO_BACKEND", default=False)
        logger.info(f"Using CPO Backend: {self.use_cpo_backend}")

        # Indicates whether or not the installation/update of a contract certificate
        # shall be offered to the EV. Should be configurable via OCPP messages.
        # Must be one of the bool values True or False
        self.allow_cert_install_service = env.bool(
            "ALLOW_CERT_INSTALL_SERVICE", default=True
        )

        # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
        # the protocols are listed here determines the priority (i.e. first list entry
        # has higher priority than second list entry). A list entry must be a member
        # of the Protocol enum
        protocols = env.list("PROTOCOLS", default=self.default_protocols)
        self.load_requested_protocols(protocols)

        # Supported authentication options (named payment options in ISO 15118-2).
        # Note: SECC will not offer 'pnc' if chosen transport protocol is not TLS
        # Must be a list containing either AuthEnum members EIM (for External
        # Identification Means), PNC (for Plug & Charge) or both
        auth_modes = env.list("AUTH_MODES", default=self.default_auth_modes)
        self.load_requested_auth_modes(auth_modes)

        # Whether the charging station allows the EV to go into Standby (one of the
        # enum values in PowerDeliveryReq's ChargeProgress field). In Standby, the
        # EV can still use value-added services while not consuming any power.
        self.standby_allowed = env.bool("STANDBY_ALLOWED", default=False)

        env.seal()  # raise all errors at once, if any

    def load_requested_protocols(self, read_protocols: Optional[List[str]]):
        protocols = format_list(read_protocols)
        valid_protocols = list(set(protocols).intersection(self.default_protocols))
        if not valid_protocols:
            raise NoSupportedProtocols(
                f"No supported protocols configured. Supported protocols are "
                f"{self.default_protocols} and could be configured in .env"
                f" file with key 'PROTOCOLS'"
            )
        self.supported_protocols = [Protocol[x] for x in valid_protocols]
        logger.info(f"Loaded protocols: {valid_protocols}")

    def load_requested_auth_modes(self, read_auth_modes: Optional[List[str]]):
        auth_modes = format_list(read_auth_modes)
        valid_auth_options = list(set(auth_modes).intersection(self.default_auth_modes))
        if not valid_auth_options:
            raise NoSupportedAuthenticationModes(
                f"No supported authentication modes configured. Supported auth modes"
                f" are {self.default_auth_modes} and could be configured in .env"
                f" file with key 'AUTH_MODES'"
            )
        self.supported_auth_options = [AuthEnum[x] for x in valid_auth_options]
        logger.info(f"Loaded authentication modes: {valid_auth_options}")
