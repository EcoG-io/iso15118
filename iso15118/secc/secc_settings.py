import environs
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.shared.messages.enums import Protocol, AuthEnum


env = environs.Env(eager=False)

env.read_env()  # read .env

# Choose the EVController implementation. Must be the class name of the controller
# that implements the EVControllerInterface
EVSE_CONTROLLER = SimEVSEController

# Supported protocols, used for SupportedAppProtocol (SAP). The order in which
# the protocols are listed here determines the priority (i.e. first list entry
# has higher priority than second list entry). A list entry must be a member
# of the Protocol enum
SUPPORTED_PROTOCOLS = [
    Protocol.ISO_15118_2,
    Protocol.ISO_15118_20_AC,
]

# This timer is set in docker-compose.dev.yml, for merely debugging and dev
# reasons
NETWORK_INTERFACE = env.str("NETWORK_INTERFACE", default="eth0")

# Supported authentication options (named payment options in ISO 15118-2).
# Note: SECC will not offer 'pnc' if chosen transport protocol is not TLS
# Must be a list containing either AuthEnum members EIM (for External
# Identification Means), PNC (for Plug & Charge) or both
SUPPORTED_AUTH_OPTIONS = [AuthEnum.EIM, AuthEnum.PNC]

# Indicates whether or not the ChargeService (energy transfer) is free.
# Should be configurable via OCPP messages.
# Must be one of the bool values True or False
FREE_CHARGING_SERVICE = env.bool("FREE_CHARGING_SERVICE", default=False)

# Indicates whether or not the installation of a contract certificate is free.
# Should be configurable via OCPP messages.
# Must be one of the bool values True or False
FREE_CERT_INSTALL_SERVICE = env.bool("FREE_CERT_INSTALL_SERVICE",
                                     default=True)

# Indicates whether or not the installation/update of a contract certificate
# shall be offered to the EV. Should be configurable via OCPP messages.
# Must be one of the bool values True or False
ALLOW_CERT_INSTALL_SERVICE = env.bool("ALLOW_CERT_INSTALL_SERVICE", default=True)

# Indicates whether or not the SECC should always enforce a TLS-secured communication
# session. If True, the SECC will only fire up a TCP server with an SSL session context
# and ignore the Security byte value from the SDP request.
ENFORCE_TLS = env.bool("SECC_ENFORCE_TLS", default=False)

env.seal()  # raise all errors at once, if any

