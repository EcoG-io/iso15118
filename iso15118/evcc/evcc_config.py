import json
import logging
from typing import List, Optional

from aiofile import async_open
from pydantic import BaseModel, Field, validator

from iso15118.shared.messages.enums import UINT_16_MAX

logger = logging.getLogger(__name__)


class EVCCConfig(BaseModel):
    supported_energy_services: List[str] = Field(
        None, max_items=4, alias="supportedEnergyServices"
    )
    is_cert_install_needed: bool = Field(None, alias="isCertInstallNeeded")
    # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
    # the EVCC shall send in the SDP request
    use_tls: Optional[bool] = Field(None, alias="useTls")
    sdp_retry_cycles: Optional[int] = Field(None, alias="sdpRetryCycles")
    max_contract_certs: Optional[int] = Field(None, alias="maxContractCerts")
    enforce_tls: bool = Field(None, alias="EnforceTls")
    supported_protocols: Optional[List[str]] = Field(
        None, max_items=4, alias="supportedProtocols"
    )
    max_supporting_points: Optional[int] = Field(None, alias="maxSupportingPoints")

    @validator("supported_energy_services", pre=True, always=True)
    def check_supported_energy_services(cls, value):
        if value is None:
            return ["AC"]
        return value

    @validator("supported_protocols", pre=True, always=True)
    def check_supported_protocols(cls, value):
        # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
        # the protocols are listed here determines the priority (i.e. first list entry
        # the protocols are listed here determines the priority (i.e. first list entry
        # has higher priority than second list entry). A list entry must be a member
        # of the Protocol enum
        if value is None:
            return [
                "ISO_15118_2",
                "ISO_15118_20_AC",
                "DIN_SPEC_70121",
            ]
        return value

    @validator("max_supporting_points", pre=True, always=True)
    def check_max_supporting_points(cls, value):
        # Indicates the maximum number of entries the EVCC supports within the
        # sub-elements of a ScheduleTuple (e.g. PowerScheduleType and PriceRuleType in
        # ISO 15118-20 as well as PMaxSchedule and SalesTariff in ISO 15118-2).
        # The SECC must not transmit more entries than defined in this parameter.
        if value is None:
            return 1024
        if not 0 <= value <= 1024:
            raise ValueError(
                "Wrong range for max_supporting_points in config file. "
                "Should be in [0..1024]"
            )
        return value

    @validator("sdp_retry_cycles", pre=True, always=True)
    def check_sdp_retry_cycle(cls, value):
        # How often shall SDP (SECC Discovery Protocol) retries happen before reverting
        # to using nominal duty cycle PWM-based charging?
        if value is None:
            return 1
        if value < 0:
            raise ValueError(
                "Wrong range for sdp_retry_cycles in config file. " "Should be in [0..]"
            )
        return value

    @validator("use_tls", pre=True, always=True)
    def check_use_tls(cls, value):
        # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
        # the EVCC shall send in the SDP request
        if value is None:
            return True
        return value

    @validator("enforce_tls", pre=True, always=True)
    def check_enforce_tls(cls, value):
        # Indicates whether or not the EVCC should always enforce a TLS-secured
        # communication session.
        # If True, the EVCC will only continue setting up a communication session if
        # the SECC's SDP response has the Security field set
        # to the enum value Security.TLS.
        # If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
        # ENFORCE_TLS overrules USE_TLS.
        if value is None:
            return False
        return value

    @validator("max_contract_certs", pre=True, always=True)
    def check_max_contract_certs(cls, value):
        # For ISO 15118-20 only
        # Maximum amount of contract certificates (and associated certificate chains)
        # the EV can store. That value is used in the CertificateInstallationReq.
        # Must be an integer between 0 and 65535, should be bigger than 0.
        if value is None:
            return 3
        if not 1 < value < UINT_16_MAX:
            raise ValueError(
                "Wrong range for max_contract_certs in config file. "
                "Should be in [1..UINT_16_MAX]"
            )
        return value


async def load_from_file(file_name: str) -> EVCCConfig:
    try:
        async with async_open(file_name, "r") as f:
            json_content = await f.read()
            data = json.loads(json_content)
            ev_config = EVCCConfig(**data)
            logger.info("EVCC Settings")
            for key, value in ev_config.dict().items():
                logger.info(f"{key:30}: {value}")
        return ev_config
    except Exception as err:
        logger.debug(f"Error on loading evcc config file:{err}")
