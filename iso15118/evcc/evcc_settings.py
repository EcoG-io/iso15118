import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import environs
from marshmallow.validate import Range

from iso15118.shared.messages.enums import UINT_16_MAX, Protocol
from iso15118.shared.network import validate_nic

logger = logging.getLogger(__name__)


@dataclass
class Config:
    iface: Optional[str] = None
    log_level: Optional[int] = None
    sdp_retry_cycles: Optional[int] = None
    max_contract_certs: Optional[int] = None
    use_tls: bool = True
    enforce_tls: bool = False
    supported_protocols: Optional[List[Protocol]] = None
    max_supporting_points: Optional[int] = None

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

        self.log_level = env.str("LOG_LEVEL", default="INFO")

        # How often shall SDP (SECC Discovery Protocol) retries happen before reverting
        # to using nominal duty cycle PWM-based charging?
        self.sdp_retry_cycles = env.int(
            "SDP_RETRY_CYCLES", default=1, validate=lambda n: n > 0
        )

        # For ISO 15118-20 only
        # Maximum amount of contract certificates (and associated certificate chains)
        # the EV can store. That value is used in the CertificateInstallationReq.
        # Must be an integer between 0 and 65535, should be bigger than 0.
        self.max_contract_certs = env.int(
            "MAX_CONTRACT_CERTS", default=3, validate=Range(min=1, max=UINT_16_MAX)
        )

        # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
        # the EVCC shall send in the SDP request
        self.use_tls = env.bool("EVCC_USE_TLS", default=True)

        # Indicates whether or not the EVCC should always enforce a TLS-secured
        # communication session.
        # If True, the EVCC will only continue setting up a communication session if
        # the SECC's SDP response has the Security field set
        # to the enum value Security.TLS.
        # If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
        # ENFORCE_TLS overrules USE_TLS.
        self.enforce_tls = env.bool("EVCC_ENFORCE_TLS", default=False)

        # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
        # the protocols are listed here determines the priority (i.e. first list entry
        # has higher priority than second list entry). A list entry must be a member
        # of the Protocol enum
        self.supported_protocols = [
            Protocol.ISO_15118_2,
            Protocol.ISO_15118_20_AC,
            Protocol.DIN_SPEC_70121,
        ]

        # Indicates the maximum number of entries the EVCC supports within the
        # sub-elements of a ScheduleTuple (e.g. PowerScheduleType and PriceRuleType in
        # ISO 15118-20 as well as PMaxSchedule and SalesTariff in ISO 15118-2).
        # The SECC must not transmit more entries than defined in this parameter.
        self.max_supporting_points = env.int(
            "MAX_SUPPORTING_POINTS", default=1024, validate=Range(min=0, max=1024)
        )

        env.seal()  # raise all errors at once, if any


RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None
