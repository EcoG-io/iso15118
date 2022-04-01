"""
This module contains the EVCC's States used to process the SECC's incoming
V2GMessage objects of the ISO 15118-20 protocol, from SessionSetupRes to
SessionStopRes.
"""

import logging
import time
from typing import Union

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.states.evcc_state import StateEVCC
from iso15118.shared.exceptions import PrivateKeyReadError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.enums import AuthEnum, Namespace
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    EIMAuthReqParams,
    PnCAuthReqParams,
    SessionSetupRes,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    RootCertificateID,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.iso15118_20.timeouts import Timeouts
from iso15118.shared.messages.xmldsig import X509IssuerSerial
from iso15118.shared.security import (
    CertPath,
    KeyEncoding,
    KeyPath,
    create_signature,
    get_cert_issuer_serial,
    load_cert_chain,
    load_priv_key,
)

logger = logging.getLogger(__name__)


# ============================================================================
# |    COMMON EVCC STATES (FOR ALL ENERGY TRANSFER MODES) - ISO 15118-20     |
# ============================================================================


class SessionSetup(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a SessionSetupRes from
    the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        # TODO: less the time used for waiting for and processing the
        #       SDPResponse and SupportedAppProtocolRes
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        msg = self.check_msg_v20(message, SessionSetupRes)
        if not msg:
            return

        session_setup_res: SessionSetupRes = msg

        self.comm_session.session_id = msg.header.session_id
        self.comm_session.evse_id = session_setup_res.evse_id

        auth_setup_req = AuthorizationSetupReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id, timestamp=time.time()
            )
        )

        self.create_next_message(
            AuthorizationSetup,
            auth_setup_req,
            Timeouts.AUTHORIZATION_SETUP_REQ,
            Namespace.ISO_V20_COMMON_MSG,
        )


class AuthorizationSetup(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an AuthorizationSetupRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.AUTHORIZATION_SETUP_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        msg = self.check_msg_v20(message, AuthorizationSetupRes)
        if not msg:
            return

        auth_setup_res: AuthorizationSetupRes = msg
        signature = None

        if (
            auth_setup_res.cert_install_service
            and self.comm_session.ev_controller.is_cert_install_needed()
        ):
            # TODO: Find a more generic way to serach for all available
            #       V2GRootCA certificates
            issuer, serial = get_cert_issuer_serial(CertPath.V2G_ROOT_DER)

            oem_prov_cert_chain = load_cert_chain(
                protocol=self.comm_session.protocol,
                leaf_path=CertPath.OEM_LEAF_DER,
                sub_ca2_path=CertPath.OEM_SUB_CA2_DER,
                sub_ca1_path=CertPath.OEM_SUB_CA1_DER,
                id="id1",
            )

            # TODO: Check how a signature in ISO 15118-20 differs from an
            #       ISO 15118-2 signature
            try:
                signature = create_signature(
                    [
                        (
                            oem_prov_cert_chain.id,
                            EXI().to_exi(
                                oem_prov_cert_chain, Namespace.ISO_V20_COMMON_MSG
                            ),
                        )
                    ],
                    load_priv_key(KeyPath.OEM_LEAF_PEM, KeyEncoding.PEM),
                )

                cert_install_req = CertificateInstallationReq(
                    header=MessageHeader(
                        session_id=self.comm_session.session_id,
                        timestamp=time.time(),
                        signature=signature,
                    ),
                    oem_prov_cert_chain=oem_prov_cert_chain,
                    list_of_root_cert_ids=[
                        RootCertificateID(
                            x509_issuer_serial=X509IssuerSerial(
                                x509_issuer_name=issuer, x509_serial_number=serial
                            )
                        )
                    ],
                    max_contract_cert_chains=self.comm_session.config.max_contract_certs,  # noqa: E501
                    prioritized_emaids=self.comm_session.ev_controller.get_prioritised_emaids(),  # noqa: E501
                )

                self.create_next_message(
                    CertificateInstallation,
                    cert_install_req,
                    Timeouts.CERTIFICATE_INSTALLATION_REQ,
                    Namespace.ISO_V20_COMMON_MSG,
                )
            except PrivateKeyReadError as exc:
                self.stop_state_machine(
                    "Can't read private key necessary to sign "
                    f"CertificateInstallationReq: {exc}"
                )
                return

        else:
            eim_params, pnc_params = None, None
            if AuthEnum.PNC in auth_setup_res.auth_services:
                # TODO Check if several contract certificates are in place and
                #      if the SECC sent a list of supported providers to pre-
                #      select the contract certificate(s) that work at this SECC
                pnc_params = PnCAuthReqParams(
                    gen_challenge=auth_setup_res.pnc_as_res.gen_challenge,
                    contract_cert_chain=load_cert_chain(
                        protocol=self.comm_session.protocol,
                        leaf_path=CertPath.CONTRACT_LEAF_DER,
                        sub_ca2_path=CertPath.MO_SUB_CA2_DER,
                        sub_ca1_path=CertPath.MO_SUB_CA1_DER,
                    ),
                    id="id1",
                )

                # TODO Need a signature for ISO 15118-20, not ISO 15118-2
                try:
                    signature = create_signature(
                        [
                            (
                                pnc_params.id,
                                EXI().to_exi(pnc_params, Namespace.ISO_V20_COMMON_MSG),
                            )
                        ],
                        load_priv_key(KeyPath.OEM_LEAF_PEM, KeyEncoding.PEM),
                    )
                except PrivateKeyReadError as exc:
                    self.stop_state_machine(
                        "Can't read private key necessary to sign "
                        f"AuthorizationReq: {exc}"
                    )
                    return
            else:
                eim_params = EIMAuthReqParams()

            auth_req = AuthorizationReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                    signature=signature,
                ),
                selected_auth_service=AuthEnum.PNC if pnc_params else AuthEnum.EIM,
                pnc_params=pnc_params,
                eim_params=eim_params,
            )

            self.create_next_message(
                Authorization,
                auth_req,
                Timeouts.AUTHORIZATION_REQ,
                Namespace.ISO_V20_COMMON_MSG,
            )


class CertificateInstallation(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    CertificateInstallationRes from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.CERTIFICATE_INSTALLATION_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("CertificateInstallation not yet implemented")


class Authorization(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an AuthorizationRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.AUTHORIZATION_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("CertificateInstallation not yet implemented")


# ============================================================================
# |                AC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class ACChargeParameterDiscovery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an
    ACChargeParameterDiscoveryReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.CHARGE_PARAMETER_DISCOVERY_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("ACChargeParameterDiscovery not yet implemented")


class ACChargeLoop(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an
    ACChargeLoopReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.AC_CHARGE_LOOP_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("ACChargeLoop not yet implemented")


# ============================================================================
# |                DC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class DCChargeParameterDiscovery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCChargeParameterDiscoveryReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.CHARGE_PARAMETER_DISCOVERY_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("DCChargeParameterDiscovery not yet implemented")


class DCCableCheck(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCCableCheckReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.DC_CABLE_CHECK_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("DCCableCheck not yet implemented")


class DCPreCharge(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCPreChargeReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.DC_PRE_CHARGE_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("DCPreCharge not yet implemented")


class DCChargeLoop(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCChargeLoopReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.DC_CHARGE_LOOP_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("DCChargeLoop not yet implemented")


class DCWeldingDetection(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCWeldingDetectionReq from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.DC_WELDING_DETECTION_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("DCWeldingDetection not yet implemented")
