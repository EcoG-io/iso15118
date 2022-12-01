import json
import logging
from dataclasses import dataclass, field, asdict, fields
from enum import Enum
from typing import List, Optional

import dacite
from aiofile import async_open
from dacite import from_dict, Config

from iso15118.shared.messages.enums import Protocol, UINT_16_MAX, ServiceV20

logger = logging.getLogger(__name__)


class SupportedProtocolOption(Enum):
    ISO_15118_2 = "ISO_15118_2"
    DIN_SPEC_70121 = "DIN_SPEC_70121"
    ISO_15118_20_AC = "ISO_15118_20_AC"
    ISO_15118_20_DC = "ISO_15118_20_DC"
    ISO_15118_20_WPT = "ISO_15118_20_WPT"
    ISO_15118_20_ACDP = "ISO_15118_20_ACDP"


@dataclass
class EVCCConfig:
    supported_energy_services: List[ServiceV20] = None
    supports_eim: bool = True
    is_cert_install_needed: bool = True
    # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
    # the EVCC shall send in the SDP request
    use_tls: bool = True
    sdp_retry_cycles: Optional[int] = 1
    max_contract_certs: Optional[int] = None
    enforce_tls: bool = False
    supported_protocols: Optional[List[str]] = None
    max_supporting_points: Optional[int] = None
    is_cert_install_needed: bool = True
    supported_energy_services: Optional[List[str]] = None

    def __post_init__(self):
        # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
        # the protocols are listed here determines the priority (i.e. first list entry
        # the protocols are listed here determines the priority (i.e. first list entry
        # has higher priority than second list entry). A list entry must be a member
        # of the Protocol enum
        if self.supported_protocols is None:
            self.supported_protocols = [
                "ISO_15118_2",
                "ISO_15118_20_AC",
                "DIN_SPEC_70121",
            ]
        for protocol in self.supported_protocols:
            if protocol not in list(map(lambda p: p.name, Protocol)):
                raise Exception("Wrong attribute for supported protocol in config file."
                                f"Should be in list "
                                f"{list(map(lambda p: p.name, Protocol))}")

        # Indicates the maximum number of entries the EVCC supports within the
        # sub-elements of a ScheduleTuple (e.g. PowerScheduleType and PriceRuleType in
        # ISO 15118-20 as well as PMaxSchedule and SalesTariff in ISO 15118-2).
        # The SECC must not transmit more entries than defined in this parameter.
        if self.max_supporting_points is None:
            self.max_supporting_points = 1024

        if not 0 <= self.max_supporting_points <= 1024:
            raise Exception("Wrong range for max_supporting_points in config file. "
                            "Should be in [0..1024]")
        # How often shall SDP (SECC Discovery Protocol) retries happen before reverting
        # to using nominal duty cycle PWM-based charging?
        if self.sdp_retry_cycles is None:
            self.sdp_retry_cycles = 1
        if self.sdp_retry_cycles < 0:
            raise Exception("Wrong range for sdp_retry_cycles in config file. "
                            "Should be in [0..]")
        # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
        # the EVCC shall send in the SDP request
        if self.use_tls is None:
            self.use_tls = True

        # Indicates whether or not the EVCC should always enforce a TLS-secured
        # communication session.
        # If True, the EVCC will only continue setting up a communication session if
        # the SECC's SDP response has the Security field set
        # to the enum value Security.TLS.
        # If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
        # ENFORCE_TLS overrules USE_TLS.
        if self.enforce_tls is None:
            self.enforce_tls = False

        # For ISO 15118-20 only
        # Maximum amount of contract certificates (and associated certificate chains)
        # the EV can store. That value is used in the CertificateInstallationReq.
        # Must be an integer between 0 and 65535, should be bigger than 0.
        if self.max_contract_certs is None:
            self.max_contract_certs = 3
        if not 1 < self.max_contract_certs < UINT_16_MAX:
            raise Exception("Wrong range for max_contract_certs in config file. "
                            "Should be in [1..UINT_16_MAX]")


async def load_from_file(file_name: str) -> EVCCConfig:
    try:
        async with async_open(file_name, "r") as f:
            json_content = await f.read()
            data = json.loads(json_content)
            ev_config = dacite.from_dict(
                data_class=EVCCConfig,
                data=data,
                config=dacite.Config(cast=[Enum]),
            )
            logger.info("EVCC Settings")
            for setting in fields(EVCCConfig):
                logger.info(f"{setting.name:30}: {getattr(ev_config, setting.name)}")

            return ev_config
    except Exception as err:
        logger.debug(f"Error on loading evcc config file:{err}")
