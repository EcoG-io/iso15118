import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional, Type, Union

import environs

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.messages.enums import AuthEnum, Protocol
from iso15118.shared.settings import shared_settings
from iso15118.shared.utils import (
    enum_to_str,
    load_requested_auth_modes,
    load_requested_protocols,
)

logger = logging.getLogger(__name__)


@dataclass
class Config:
    iface: Optional[str] = None
    log_level: Union[str, int] = None
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
        self.supported_protocols = load_requested_protocols(protocols)

        # Supported authentication options (named payment options in ISO 15118-2).
        # Note: SECC will not offer 'pnc' if chosen transport protocol is not TLS
        # Must be a list containing either AuthEnum members EIM (for External
        # Identification Means), PNC (for Plug & Charge) or both
        auth_modes = env.list("AUTH_MODES", default=self.default_auth_modes)
        self.supported_auth_options = load_requested_auth_modes(auth_modes)

        # Whether the charging station allows the EV to go into Standby (one of the
        # enum values in PowerDeliveryReq's ChargeProgress field). In Standby, the
        # EV can still use value-added services while not consuming any power.
        self.standby_allowed = env.bool("STANDBY_ALLOWED", default=False)

        env.seal()  # raise all errors at once, if any
        logger.info("SECC settings:")
        for key, value in shared_settings.items():
            logger.info(f"{key.upper():30}: {value}")
        for key, value in env.dump().items():
            logger.info(f"{key:30}: {value}")

    def _get_from_dict(
        self, dictionary: dict, key: str, type_of_value: Type = str, default=None
    ) -> Any:
        """
        Find a key in a dictionary, convert its associated value to a new type,
        and return the result.

        Args:
        dictionary (dict): The dictionary to search in.
        key: The key to find in the dictionary.
        new_type (type): The target type to convert the value to.
        default: The default value to return if the key is not found in the
        dictionary (optional).

        Returns:
        The value associated with the key, converted to the new_type, or the default
        value if the key is not found.
        """
        if key in dictionary:
            if type(dictionary[key]) is type_of_value:
                return dictionary[key]
            try:
                if type_of_value == bool:
                    return dictionary[key].lower() == "true"
                elif type_of_value == list:
                    return dictionary[key].split(",")
                else:
                    return type(dictionary[key])
            except (ValueError, TypeError):
                return default
        else:
            return default

    def update_shared_settings(self, new_config: dict):
        try:
            for key, value in new_config.items():
                current_value = shared_settings[key]
                shared_settings.update(
                    {
                        key: self._get_from_dict(
                            new_config, key, type(current_value), current_value
                        )
                    }
                )
        except KeyError as exc:
            logger.error(f"{exc}")

    def update(self, new_config: dict):
        for key, value in new_config.items():
            old_value = self.get_value_str(key)
            if key in shared_settings.keys():
                self.update_shared_settings(new_config)
            elif key in self.as_dict().keys():
                current_value = self.as_dict()[key]
                update_value = self._get_from_dict(
                    new_config, key, type(current_value), current_value
                )
                if current_value == update_value:
                    continue
                if key == "supported_auth_options":
                    update_value = load_requested_auth_modes(update_value)
                elif key == "supported_protocols":
                    update_value = load_requested_protocols(update_value)
                elif key == "log_level":
                    logging.getLogger().setLevel(value)
                self.as_dict().update({key: update_value})
            else:
                raise ValueError("Key is not in the config")
            logger.info(
                f"Config is updated key = {key}: old value = "
                f"{old_value} - new value = {self.get_value_str(key)}"
            )

    def as_dict(self):
        return self.__dict__

    def get_value(self, key):
        if key in shared_settings.keys():
            return shared_settings[key]
        else:
            return self.as_dict()[key]

    def get_value_str(self, key) -> Optional[str]:
        if key in shared_settings.keys():
            value = shared_settings[key]
        elif key in self.as_dict().keys():
            value = self.as_dict()[key]
        else:
            return None

        if type(value) is list and all(isinstance(item, Enum) for item in value):
            value = [enum_to_str(v) for v in value]
        return str(value)
