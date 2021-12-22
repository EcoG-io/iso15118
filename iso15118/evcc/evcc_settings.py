import logging
import os
from dataclasses import dataclass
from typing import Optional, Type, List
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.controller.interface import EVControllerInterface
from iso15118.shared.messages.enums import Protocol
from iso15118.shared.network import validate_nic

import environs
from marshmallow.validate import Range


logger = logging.getLogger(__name__)


@dataclass
class Config:
    iface: Optional[str] = None
    redis_host: Optional[str] = None
    redis_port: Optional[int] = None
    log_level: Optional[int] = None
    ev_controller: Type[EVControllerInterface] = None
    sdp_retry_cycles: Optional[int] = None
    max_contract_certs: Optional[int] = None
    use_tls: bool = True
    enforce_tls: bool = False
    supported_protocols: Optional[List[Protocol]] = None

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
        # validate the NIC selected
        validate_nic(self.iface)

        # Redis Configuration
        self.redis_host = env.str("REDIS_HOST", default='localhost')
        self.redis_port = env.int("REDIS_PORT", default=6379)

        self.log_level = env.str("LOG_LEVEL", default="INFO")

        # Choose the EVController implementation. Must be the class name of the controller
        # that implements the EVControllerInterface
        self.ev_controller = EVControllerInterface
        if env.bool("EVCC_CONTROLLER_SIM", default=False):
            self.ev_controller = SimEVController

        # How often shall SDP (SECC Discovery Protocol) retries happen before reverting
        # to using nominal duty cycle PWM-based charging?
        self.sdp_retry_cycles = env.int("SDP_RETRY_CYCLES", default=1,
                                        validate=lambda n: n > 0)

        # For ISO 15118-20 only
        # Maximum amount of contract certificates (and associated certificate chains)
        # the EV can store. That value is used in the CertificateInstallationReq.
        # Must be an integer between 0 and 65535, should be bigger than 0.
        self.max_contract_certs = env.int("MAX_CONTRACT_CERTS", default=3,
                                          validate=Range(min=1, max=65535))

        # Indicates the security level (either TCP (unencrypted) or TLS (encrypted)) the EVCC
        # shall send in the SDP request
        self.use_tls = env.bool("EVCC_USE_TLS", default=True)

        # Indicates whether or not the EVCC should always enforce a TLS-secured communication
        # session. If True, the EVCC will only continue setting up a communication session if
        # the SECC's SDP response has the Security field set to the enum value Security.TLS.
        # If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
        # ENFORCE_TLS overrules USE_TLS.
        self.enforce_tls = env.bool("EVCC_ENFORCE_TLS", default=False)

        # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
        # the protocols are listed here determines the priority (i.e. first list entry
        # has higher priority than second list entry). A list entry must be a member
        # of the Protocol enum
        self.supported_protocols = [Protocol.ISO_15118_2,
                                    Protocol.ISO_15118_20_AC]

        env.seal()  # raise all errors at once, if any


RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None