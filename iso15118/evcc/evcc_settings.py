import environs
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.shared.messages.enums import Protocol

# Choose the EVController implementation. Must be the class name of the controller
# that implements the EVControllerInterface
EV_CONTROLLER = SimEVController

env = environs.Env(eager=False)

env.read_env()  # read .env

# Supported protocols, used for SupportedAppProtocol (SAP). The order in which
# the protocols are listed here determines the priority (i.e. first list entry
# has higher priority than second list entry). A list entry must be a member
# of the Protocol enum
SUPPORTED_PROTOCOLS = [
    Protocol.ISO_15118_2,
    Protocol.ISO_15118_20_AC,
]


# Provide the name of a specific network interface card (NIC, like 'en0') here.
# If no NIC is provided, the list of NICs is scanned and the first one that has
# an IPv6 address with a local-link address is chosen.
NETWORK_INTERFACE = env.str("NETWORK_INTERFACE", default="eth0")

# How often shall SDP (SECC Discovery Protocol) retries happen before reverting
# to using nominal duty cycle PWM-based charging?
SDP_RETRY_CYCLES = env.int("SDP_RETRY_CYCLES", default=1)

# === PAUSING RELATED INFORMATION ===
# If a charging session needs to be paused, the EVCC needs to persist certain
# information that must be provided again once the communication session
# resumes. This information includes:
# - Session ID: int or None
# - Selected authorization option: must be a member of AuthEnum enum or None
# - Requested energy transfer mode: must be a member of EnergyTransferModeEnum
#                                   or None
# TODO Check what ISO 15118-20 demands for pausing
RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None

# For ISO 15118-20 only
# Maximum amount of contract certificates (and associated certificate chains)
# the EV can store. That value is used in the CertificateInstallationReq.
# Must be an integer between 0 and 65535, should be bigger than 0.
MAX_CONTRACT_CERTS = env.int("MAX_CONTRACT_CERTS", default=3)

# Indicates the security level (either TCP (unencrypted) or TLS (encrypted)) the EVCC
# shall send in the SDP request
USE_TLS = env.bool("USE_TLS", default=True)

# Indicates whether or not the EVCC should always enforce a TLS-secured communication
# session. If True, the EVCC will only continue setting up a communication session if
# the SECC's SDP response has the Security field set to the enum value Security.TLS.
# If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
# ENFORCE_TLS overrules USE_TLS.
ENFORCE_TLS = env.bool("EVCC_ENFORCE_TLS", default=False)

env.seal()  # raise all errors at once, if any

