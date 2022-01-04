"""
This module contains the EVCC's States used to process the SECC's incoming
V2GMessage objects of the ISO 15118-20 protocol, from SessionSetupRes to
SessionStopRes.
"""

import logging
import time
from typing import Union, List

from iso15118.evcc.comm_session_handler import EVCCCommunicationSession
from iso15118.evcc.states.evcc_state import StateEVCC
from iso15118.shared.exceptions import PrivateKeyReadError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.enums import (
    AuthEnum,
    Namespace,
    ServiceV20,
    ISOV20PayloadTypes,
    ParameterName,
    ControlMode,
)
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    EIMAuthReqParams,
    PnCAuthReqParams,
    SessionSetupRes,
    AuthorizationRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServiceDetailReq,
    SessionStopReq,
    ChargingSession,
    ServiceDetailRes,
    ServiceSelectionReq,
    SelectedService,
    ServiceSelectionRes,
    ScheduleExchangeReq,
    OfferedService,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    RootCertificateIDList,
    Processing,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.iso15118_20.dc import (
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryRes,
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
            V2GMessageDINSPEC,
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
            ISOV20PayloadTypes.MAINSTREAM,
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
            V2GMessageDINSPEC,
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
            # TODO: Find a more generic way to search for all available
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
                    root_cert_id_list=RootCertificateIDList(
                        root_cert_ids=[
                            X509IssuerSerial(
                                x509_issuer_name=issuer, x509_serial_number=serial
                            )
                        ]
                    ),
                    max_contract_cert_chains=self.comm_session.config.max_contract_certs,
                    prioritized_emaids=self.comm_session.ev_controller.get_prioritised_emaids(),
                )

                self.create_next_message(
                    CertificateInstallation,
                    cert_install_req,
                    Timeouts.CERTIFICATE_INSTALLATION_REQ,
                    Namespace.ISO_V20_COMMON_MSG,
                )
                return
            except PrivateKeyReadError as exc:
                logger.warning(
                    "PrivateKeyReadError occurred while trying to create "
                    "signature for CertificateInstallationReq. Falling back to sending "
                    f"AuthorizationReq instead.\n{exc}"
                )

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
                            to_exi(pnc_params, Namespace.ISO_V20_COMMON_MSG),
                        )
                    ],
                    load_priv_key(KeyPath.CONTRACT_LEAF_PEM, KeyEncoding.PEM),
                )
            except PrivateKeyReadError as exc:
                logger.warning(
                    "PrivateKeyReadError occurred while trying to create "
                    "signature for PnC_AReqAuthorizationMode. Falling back to EIM "
                    f"identification mode.\n{exc}"
                )
                pnc_params = None
                eim_params = EIMAuthReqParams()
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
            ISOV20PayloadTypes.MAINSTREAM,
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
        msg = self.check_msg_v20(message, AuthorizationRes)
        if not msg:
            return

        auth_res: AuthorizationRes = msg
        # TODO Act upon the response codes and evse_processing value of auth_res
        # TODO: V2G20-2221 demands to send CertificateInstallationReq if necessary

        service_discovery_req = ServiceDiscoveryReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            )
            # To limit the list of requested VAS services, set supported_service_ids
        )

        self.create_next_message(
            ServiceDiscovery,
            service_discovery_req,
            Timeouts.SERVICE_DISCOVERY_REQ,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )


class ServiceDiscovery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a ServiceDiscoveryRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.SERVICE_DISCOVERY_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        msg = self.check_msg_v20(message, ServiceDiscoveryRes)
        if not msg:
            return

        service_discovery_res: ServiceDiscoveryRes = msg

        self.comm_session.service_renegotiation_supported = (
            service_discovery_res.service_renegotiation_supported
        )

        req_energy_service: ServiceV20 = (
            self.comm_session.ev_controller.get_energy_service()
        )

        matched_energy_service: bool = False
        for energy_service in service_discovery_res.energy_service_list.services:
            self.comm_session.offered_services_v20.append(
                OfferedService(
                    service=ServiceV20.get_by_id(energy_service.service_id),
                    is_energy_service=True,
                    is_free=energy_service.free_service,
                    # Parameter sets are available with ServiceDetailRes
                    parameter_sets=[],
                )
            )

            if req_energy_service == ServiceV20.get_by_id(energy_service.service_id):
                matched_energy_service = True
                self.comm_session.service_details_to_request.append(
                    energy_service.service_id
                )

        if not matched_energy_service:
            session_stop_req = SessionStopReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                ),
                charging_session=ChargingSession.TERMINATE,
                # See "3.5.2. Error handling" in CharIN Implementation Guide for DC BPT
                ev_termination_code=1,
                ev_termination_explanation="WrongServiceID",
            )

            self.create_next_message(
                SessionStop,
                session_stop_req,
                Timeouts.SESSION_STOP_REQ,
                Namespace.ISO_V20_COMMON_MSG,
                ISOV20PayloadTypes.MAINSTREAM,
            )
            return

        if service_discovery_res.vas_list:
            for vas_service in service_discovery_res.vas_list.services:
                self.comm_session.offered_services_v20.append(
                    OfferedService(
                        service=ServiceV20.get_by_id(vas_service.service_id),
                        is_energy_service=False,
                        is_free=vas_service.free_service,
                        # Parameter sets are available with ServiceDetailRes
                        parameter_sets=[],
                    )
                )

                # If you want to request service details for a specific value-added
                # service, then use these lines of code:
                # self.comm_session.service_details_to_request.append(
                #     vas_service.service_id
                # )

        service_detail_req = ServiceDetailReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            ),
            service_id=self.comm_session.service_details_to_request.pop(),
        )

        self.create_next_message(
            ServiceDetail,
            service_detail_req,
            Timeouts.SERVICE_DETAIL_REQ,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )


class ServiceDetail(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a ServiceDetailRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.SERVICE_DETAIL_REQ)
        # Checks whether a control mode for the selected energy service was provided.
        # Should always be the case and is needed to distinguish between Scheduled and
        # Dynamic mode for the further messages.
        self.control_mode_found = False

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        msg = self.check_msg_v20(message, ServiceDetailRes)
        if not msg:
            return

        service_detail_res: ServiceDetailRes = msg

        self.select_services(service_detail_res)

        if not self.control_mode_found:
            session_stop_req = SessionStopReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                ),
                charging_session=ChargingSession.TERMINATE,
                ev_termination_explanation="Control mode parameter missing",
            )

            self.create_next_message(
                SessionStop,
                session_stop_req,
                Timeouts.SESSION_STOP_REQ,
                Namespace.ISO_V20_COMMON_MSG,
                ISOV20PayloadTypes.MAINSTREAM,
            )
            return

        if len(self.comm_session.service_details_to_request) > 0:
            service_detail_req = ServiceDetailReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                ),
                service_id=self.comm_session.service_details_to_request.pop(),
            )

            self.create_next_message(
                ServiceDetail,
                service_detail_req,
                Timeouts.SERVICE_DETAIL_REQ,
                Namespace.ISO_V20_COMMON_MSG,
                ISOV20PayloadTypes.MAINSTREAM,
            )

            return

        selected_vas_list: List[SelectedService] = []
        for vas in self.comm_session.selected_vas_list_v20:
            selected_vas_list.append(
                SelectedService(
                    service_id=vas.service.id, parameter_set_id=vas.parameter_set.id
                )
            )

        selected_energy_service = SelectedService(
            service_id=self.comm_session.selected_energy_service.service.id,
            parameter_set_id=self.comm_session.selected_energy_service.parameter_set.id,
        )

        service_selection_req = ServiceSelectionReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            ),
            selected_energy_service=selected_energy_service,
            selected_vas_list=selected_vas_list if len(selected_vas_list) > 0 else None,
        )

        self.create_next_message(
            ServiceSelection,
            service_selection_req,
            Timeouts.SERVICE_SELECTION_REQ,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        )

    def select_services(self, service_detail_res: ServiceDetailRes):
        requested_energy_service: ServiceV20 = (
            self.comm_session.ev_controller.get_energy_service()
        )

        for offered_service in self.comm_session.offered_services_v20:
            # Safe the parameter sets for a particular service
            if offered_service.service.id == service_detail_res.service_id:
                offered_service.parameter_sets = (
                    service_detail_res.service_parameter_list.parameter_sets
                )

                # Select the energy service and the corresponding parameter set if the
                # offered energy service is the one the EVCC requested
                if (
                    offered_service.is_energy_service
                    and offered_service.service == requested_energy_service
                ):
                    self.comm_session.selected_energy_service = (
                        self.comm_session.ev_controller.select_energy_service_v20(
                            offered_service.service,
                            offered_service.is_free,
                            offered_service.parameter_sets,
                        )
                    )

                    param_set = self.comm_session.selected_energy_service.parameter_set
                    for param in param_set.parameters:
                        if param.name == ParameterName.CONTROL_MODE:
                            self.comm_session.control_mode = ControlMode(
                                param.int_value
                            )
                            self.control_mode_found = True

                # Select the value-added service (VAS) and corresponding parameter set
                # if you want to use that service
                if not offered_service.is_energy_service:
                    selected_vas = self.comm_session.ev_controller.select_vas_v20(
                        offered_service.service,
                        offered_service.is_free,
                        offered_service.parameter_sets,
                    )

                    if selected_vas:
                        self.comm_session.selected_vas_list_v20.append(selected_vas)


class ServiceSelection(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a ServiceSelectionRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.SERVICE_SELECTION_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        msg = self.check_msg_v20(message, ServiceSelectionRes)
        if not msg:
            return

        service_selection_res: ServiceSelectionRes = msg
        # TODO Act upon the possible negative response codes in service_selection_res

        charge_params = self.comm_session.ev_controller.get_charge_params_v20(
            self.comm_session.selected_energy_service
        )

        if self.comm_session.selected_energy_service.service == ServiceV20.DC:
            next_req = DCChargeParameterDiscoveryReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                ),
                dc_params=charge_params,
            )

            self.create_next_message(
                DCChargeParameterDiscovery,
                next_req,
                Timeouts.CHARGE_PARAMETER_DISCOVERY_REQ,
                Namespace.ISO_V20_DC,
                ISOV20PayloadTypes.DC_MAINSTREAM,
            )
        elif self.comm_session.selected_energy_service.service == ServiceV20.DC_BPT:
            next_req = DCChargeParameterDiscoveryReq(
                header=MessageHeader(
                    session_id=self.comm_session.session_id,
                    timestamp=time.time(),
                ),
                bpt_dc_params=charge_params,
            )

            self.create_next_message(
                DCChargeParameterDiscovery,
                next_req,
                Timeouts.CHARGE_PARAMETER_DISCOVERY_REQ,
                Namespace.ISO_V20_DC,
                ISOV20PayloadTypes.DC_MAINSTREAM,
            )
        else:
            # TODO Implement support for other energy transfer services
            logger.error(
                "Energy transfer mode for service "
                f"{self.comm_session.selected_energy_service.service} "
                "not yet supported in ServiceSelection"
            )


class ScheduleExchange(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a ScheduleExchangeRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.SCHEDULE_EXCHANGE_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("ScheduleExchange not yet implemented")


class PowerDelivery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a PowerDeliveryRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.POWER_DELIVERY_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("PowerDelivery not yet implemented")


class SessionStop(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a SessionStopRes
    from the SECC.
    """

    def __init__(self, comm_session: EVCCCommunicationSession):
        super().__init__(comm_session, Timeouts.SESSION_STOP_REQ)

    def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
        ],
    ):
        raise NotImplementedError("SessionStop not yet implemented")


# ============================================================================
# |                AC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class ACChargeParameterDiscovery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an
    ACChargeParameterDiscoveryRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("ACChargeParameterDiscovery not yet implemented")


class ACChargeLoop(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes an
    ACChargeLoopRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("ACChargeLoop not yet implemented")


# ============================================================================
# |                DC-SPECIFIC EVCC STATES - ISO 15118-20                    |
# ============================================================================


class DCChargeParameterDiscovery(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCChargeParameterDiscoveryRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        msg = self.check_msg_v20(message, DCChargeParameterDiscoveryRes)
        if not msg:
            return

        dc_cpd_res: DCChargeParameterDiscoveryRes = msg
        # TODO Act upon the possible negative response codes in dc_cpd_res

        scheduled_params, dynamic_params = None, None
        if self.comm_session.control_mode == ControlMode.SCHEDULED:
            scheduled_params = self.comm_session.ev_controller.get_scheduled_se_params(
                self.comm_session.selected_energy_service
            )

        if self.comm_session.control_mode == ControlMode.DYNAMIC:
            dynamic_params = self.comm_session.ev_controller.get_dynamic_se_params(
                self.comm_session.selected_energy_service
            )

        schedule_exchange_req = ScheduleExchangeReq(
            header=MessageHeader(
                session_id=self.comm_session.session_id,
                timestamp=time.time(),
            ),
            max_supporting_points=self.comm_session.config.max_supporting_points,
            scheduled_params=scheduled_params,
            dynamic_params=dynamic_params,
        )

        self.create_next_message(
            ScheduleExchange,
            schedule_exchange_req,
            Timeouts.SCHEDULE_EXCHANGE_REQ,
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.SCHEDULE_RENEGOTIATION,
        )


class DCCableCheck(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCCableCheckRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("DCCableCheck not yet implemented")


class DCPreCharge(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCPreChargeRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("DCPreCharge not yet implemented")


class DCChargeLoop(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCChargeLoopRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("DCChargeLoop not yet implemented")


class DCWeldingDetection(StateEVCC):
    """
    The ISO 15118-20 state in which the EVCC processes a
    DCWeldingDetectionRes from the SECC.
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
            V2GMessageDINSPEC,
        ],
    ):
        raise NotImplementedError("DCWeldingDetection not yet implemented")
