from iso15118.shared.messages.enums import AuthEnum, Namespace, ISOV20PayloadTypes
from iso15118.shared.messages.iso15118_2.body import EMAID
from iso15118.shared.messages.iso15118_2.body import (
    AuthorizationReq as AuthorizationReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    AuthorizationRes as AuthorizationResV2,
)
from iso15118.shared.messages.iso15118_2.body import CableCheckReq, CableCheckRes
from iso15118.shared.messages.iso15118_2.body import (
    CertificateInstallationReq as CertificateInstallationReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    CertificateInstallationRes as CertificateInstallationResV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    CertificateUpdateReq,
    CertificateUpdateRes,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
    ChargingStatusReq,
    ChargingStatusRes,
    CurrentDemandReq,
    CurrentDemandRes,
    MeteringReceiptReq,
    MeteringReceiptRes,
    PaymentDetailsReq,
    PaymentDetailsRes,
    PaymentServiceSelectionReq,
    PaymentServiceSelectionRes,
)
from iso15118.shared.messages.iso15118_2.body import (
    PowerDeliveryReq as PowerDeliveryReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    PowerDeliveryRes as PowerDeliveryResV2,
)
from iso15118.shared.messages.iso15118_2.body import PreChargeReq, PreChargeRes
from iso15118.shared.messages.iso15118_2.body import (
    ServiceDetailReq as ServiceDetailReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    ServiceDetailRes as ServiceDetailResV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    ServiceDiscoveryReq as ServiceDiscoveryReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    ServiceDiscoveryRes as ServiceDiscoveryResV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    SessionSetupReq as SessionSetupReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    SessionSetupRes as SessionSetupResV2,
)
from iso15118.shared.messages.iso15118_2.body import SessionStopReq as SessionStopReqV2
from iso15118.shared.messages.iso15118_2.body import SessionStopRes as SessionStopResV2
from iso15118.shared.messages.iso15118_2.body import (
    WeldingDetectionReq as WeldingDetectionReqV2,
)
from iso15118.shared.messages.iso15118_2.body import (
    WeldingDetectionRes as WeldingDetectionResV2,
)
from iso15118.shared.messages.iso15118_2.datatypes import ACEVSEStatus, AuthOptions
from iso15118.shared.messages.iso15118_2.datatypes import (
    CertificateChain as CertificateChainV2,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ChargeService,
    DCEVSEStatus,
    DCEVSEStatusCode,
    DHPublicKey,
    EncryptedPrivateKey,
    EnergyTransferMode,
    EnergyTransferModeEnum,
    EVSENotification,
    EVSEProcessing,
    IsolationLevel,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from iso15118.shared.messages.iso15118_2.datatypes import ServiceCategory, ServiceID
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeLoopReq,
    ACChargeLoopRes,
    ACChargeParameterDiscoveryReq,
    ACChargeParameterDiscoveryRes,
    ACChargeParameterDiscoveryResParams,
    ScheduledACChargeLoopResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq as AuthorizationReqV20,
    SubCertificates,
    ServiceList,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationRes as AuthorizationResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationSetupReq,
    AuthorizationSetupRes,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    CertificateChain as CertificateChainV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    CertificateInstallationReq as CertificateInstallationReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    CertificateInstallationRes as CertificateInstallationResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    DynamicScheduleExchangeResParams,
    ECDHCurve,
    EIMAuthSetupResParams,
    MeteringConfirmationReq,
    MeteringConfirmationRes,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    PowerDeliveryReq as PowerDeliveryReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    PowerDeliveryRes as PowerDeliveryResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    PriceLevelSchedule,
    PriceLevelScheduleEntryList,
    ScheduleExchangeReq,
    ScheduleExchangeRes,
    Service,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ServiceDetailReq as ServiceDetailReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ServiceDetailRes as ServiceDetailResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ServiceDiscoveryReq as ServiceDiscoveryReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ServiceDiscoveryRes as ServiceDiscoveryResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ServiceParameterList,
    ServiceSelectionReq,
    ServiceSelectionRes,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    SessionSetupReq as SessionSetupReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    SessionSetupRes as SessionSetupResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    SessionStopReq as SessionStopReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    SessionStopRes as SessionStopResV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import SignedInstallationData
from iso15118.shared.messages.iso15118_20.common_types import (
    MessageHeader as MessageHeaderV20,
)
from iso15118.shared.messages.iso15118_20.common_types import Processing, RationalNumber
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)

# TODO: Implement DIN SPEC 70121 case (failed_response_din = {})
from iso15118.shared.messages.iso15118_20.dc import (
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryRes,
    DCChargeParameterDiscoveryResParams,
)


def init_failed_responses_iso_v2() -> dict:
    """
    Initiates a dictionary containing the XSD compliant failed responses with
    minimal payload (e.g. only mandatory fields set, bytes objects only 1 byte
    big) for ISO 15118-2 messages, as required by ISO 15118 in case of sending
    a response with a response code starting with "FAILED".

    Note: When sending the actual response, you must override the preset
          response code with the failure response code that is most fitting.
    """
    failed_response_iso_v2 = {
        SessionSetupReqV2: SessionSetupResV2(
            response_code=ResponseCodeV2.FAILED, evse_id="1234567"
        ),
        ServiceDiscoveryReqV2: ServiceDiscoveryResV2(
            response_code=ResponseCodeV2.FAILED,
            auth_option_list=[AuthOptions(value=AuthEnum.EIM_V2)],
            charge_service=ChargeService(
                service_id=ServiceID.CHARGING,
                service_category=ServiceCategory.CHARGING,
                free_service=False,
                supported_energy_transfer_mode=[
                    EnergyTransferMode(value=EnergyTransferModeEnum.DC_CORE)
                ],
            ),
        ),
        ServiceDetailReqV2: ServiceDetailResV2(
            response_code=ResponseCodeV2.FAILED, service_id=0
        ),
        PaymentServiceSelectionReq: PaymentServiceSelectionRes(
            response_code=ResponseCodeV2.FAILED
        ),
        CertificateInstallationReqV2: CertificateInstallationResV2(
            response_code=ResponseCodeV2.FAILED,
            cps_cert_chain=CertificateChainV2(certificate=bytes(0)),
            contract_cert_chain=CertificateChainV2(certificate=bytes(0)),
            encrypted_private_key=EncryptedPrivateKey(id="", value=bytes(0)),
            dh_public_key=DHPublicKey(id="", value=bytes(0)),
            emaid=EMAID(value="123456789ABCDE"),
        ),
        CertificateUpdateReq: CertificateUpdateRes(
            response_code=ResponseCodeV2.FAILED,
            cps_cert_chain=CertificateChainV2(certificate=bytes(0)),
            contract_cert_chain=CertificateChainV2(certificate=bytes(0)),
            encrypted_private_key=EncryptedPrivateKey(id="", value=bytes(0)),
            dh_public_key=DHPublicKey(id="", value=bytes(0)),
            emaid=EMAID(value="123456789ABCDE"),
        ),
        PaymentDetailsReq: PaymentDetailsRes(
            response_code=ResponseCodeV2.FAILED,
            gen_challenge=bytes(16),
            evse_timestamp=0,
        ),
        AuthorizationReqV2: AuthorizationResV2(
            response_code=ResponseCodeV2.FAILED, evse_processing=EVSEProcessing.FINISHED
        ),
        ChargeParameterDiscoveryReq:
        # TODO: Need to find a way to circumvent the root_validator
        ChargeParameterDiscoveryRes(
            response_code=ResponseCodeV2.FAILED, evse_processing=EVSEProcessing.FINISHED
        ),
        PowerDeliveryReqV2:
        # TODO: Need to find a way to circumvent the root_validator
        PowerDeliveryResV2(response_code=ResponseCodeV2.FAILED),
        ChargingStatusReq: ChargingStatusRes(
            response_code=ResponseCodeV2.FAILED,
            evse_id="1234567",
            sa_schedule_tuple_id=1,
            ac_evse_status=ACEVSEStatus(
                notification_max_delay=0,
                evse_notification=EVSENotification.NONE,
                rcd=False,
            ),
        ),
        CableCheckReq: CableCheckRes(
            response_code=ResponseCodeV2.FAILED,
            dc_evse_status=DCEVSEStatus(
                evse_notification=EVSENotification.NONE,
                notification_max_delay=0,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_processing=EVSEProcessing.FINISHED,
        ),
        PreChargeReq: PreChargeRes(
            response_code=ResponseCodeV2.FAILED,
            dc_evse_status=DCEVSEStatus(
                evse_notification=EVSENotification.NONE,
                notification_max_delay=0,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_present_voltage=PVEVSEPresentVoltage(
                multiplier=0, value=230, unit="V"
            ),
        ),
        CurrentDemandReq: CurrentDemandRes(
            response_code=ResponseCodeV2.FAILED,
            dc_evse_status=DCEVSEStatus(
                evse_notification=EVSENotification.NONE,
                notification_max_delay=0,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_present_voltage=PVEVSEPresentVoltage(
                multiplier=0, value=230, unit="V"
            ),
            evse_present_current=PVEVSEPresentCurrent(multiplier=0, value=10, unit="A"),
            evse_current_limit_achieved=False,
            evse_voltage_limit_achieved=False,
            evse_power_limit_achieved=False,
            evse_id="1234567",
            sa_schedule_tuple_id=1,
        ),
        MeteringReceiptReq:
        # TODO: Need to find a way to circumvent the root_validator
        MeteringReceiptRes(response_code=ResponseCodeV2.FAILED),
        WeldingDetectionReqV2: WeldingDetectionResV2(
            response_code=ResponseCodeV2.FAILED,
            dc_evse_status=DCEVSEStatus(
                evse_notification=EVSENotification.NONE,
                notification_max_delay=0,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_present_voltage=PVEVSEPresentVoltage(
                multiplier=0, value=230, unit="V"
            ),
        ),
        SessionStopReqV2: SessionStopResV2(response_code=ResponseCodeV2.FAILED),
    }

    return failed_response_iso_v2


def init_failed_responses_iso_v20() -> dict:
    """
    Initiates a dictionary containing the XSD compliant failed responses with
    minimal payload (e.g. only mandatory fields set, bytes objects only 1 byte
    big) for ISO 15118-20 messages, as required by ISO 15118 in case of sending
    a response with a response code starting with "FAILED".

    When sending the actual response, you must override the preset response
    code with the failure response code that is most fitting.
    """
    header = MessageHeaderV20(session_id=bytes(1).hex().upper(), timestamp=1)

    failed_response_iso_v20 = {
        SessionSetupReqV20: (
            SessionSetupResV20(
                header=header, response_code=ResponseCodeV20.FAILED, evse_id=""
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        AuthorizationReqV20: (
            AuthorizationResV20(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                evse_processing=Processing.FINISHED,
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        AuthorizationSetupReq: (
            AuthorizationSetupRes(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                auth_services=[AuthEnum.EIM],
                cert_install_service=False,
                eim_as_res=EIMAuthSetupResParams(),
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        CertificateInstallationReqV20: (
            CertificateInstallationResV20(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                evse_processing=Processing.FINISHED,
                cps_certificate_chain=CertificateChainV20(certificate=bytes(0)),
                signed_installation_data=SignedInstallationData(
                    contract_cert_chain=CertificateChainV20(
                        certificate=bytes(0),
                        sub_certificates=SubCertificates(certificate=[bytes(0)]),
                    ),
                    ecdh_curve=ECDHCurve.x448,
                    dh_public_key=bytes(0),
                    x448_encrypted_private_key=bytes(84),
                    id="",
                ),
                remaining_contract_cert_chains=0,
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        ServiceDiscoveryReqV20: (
            ServiceDiscoveryResV20(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                service_renegotiation_supported=False,
                energy_service_list=ServiceList(
                    services=[Service(service_id=0, free_service=False)],
                ),
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        ServiceDetailReqV20: (
            ServiceDetailResV20(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                service_id=0,
                service_parameter_list=ServiceParameterList(parameter_sets=[]),
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        ServiceSelectionReq: (
            ServiceSelectionRes(header=header, response_code=ResponseCodeV20.FAILED),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        ACChargeParameterDiscoveryReq: (
            ACChargeParameterDiscoveryRes(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                ac_params=ACChargeParameterDiscoveryResParams(
                    evse_max_charge_power=RationalNumber(exponent=0, value=0),
                    evse_min_charge_power=RationalNumber(exponent=0, value=0),
                    evse_nominal_frequency=RationalNumber(exponent=0, value=0),
                ),
            ),
            Namespace.ISO_V20_AC,
            ISOV20PayloadTypes.AC_MAINSTREAM,
        ),
        DCChargeParameterDiscoveryReq: (
            DCChargeParameterDiscoveryRes(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                dc_params=DCChargeParameterDiscoveryResParams(
                    evse_max_charge_power=RationalNumber(exponent=0, value=0),
                    evse_min_charge_power=RationalNumber(exponent=0, value=0),
                    evse_max_charge_current=RationalNumber(exponent=0, value=0),
                    evse_min_charge_current=RationalNumber(exponent=0, value=0),
                    evse_max_voltage=RationalNumber(exponent=0, value=0),
                    evse_min_voltage=RationalNumber(exponent=0, value=0),
                ),
            ),
            Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.DC_MAINSTREAM,
        ),
        # TODO Need to add DC messages for ISO 15118-20
        #     None,
        # WPTChargeParameterDiscoveryReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        # WPTFinePositioningSetupReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        # WPTFinePositioningReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        # WPTPairingReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        # WPTAlignmentCheckReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        # ACDPVehiclePositioningReq:
        # TODO Need to add ACDP messages for ISO 15118-20
        #     None,
        # ACDPConnectReq:
        # TODO Need to add ACDP messages for ISO 15118-20
        #     None,
        # ACDPDisconnectReq:
        # TODO Need to add ACDP messages for ISO 15118-20
        #     None,
        ScheduleExchangeReq: (
            ScheduleExchangeRes(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                evse_processing=Processing.ONGOING,
                dynamic_params=DynamicScheduleExchangeResParams(
                    price_level_schedule=PriceLevelSchedule(
                        time_anchor=0,
                        schedule_id=1,
                        num_price_levels=0,
                        schedule_entries=PriceLevelScheduleEntryList(entries=[]),
                    )
                ),
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        PowerDeliveryReqV20: (
            PowerDeliveryResV20(header=header, response_code=ResponseCodeV20.FAILED),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        ACChargeLoopReq: (
            ACChargeLoopRes(
                header=header,
                response_code=ResponseCodeV20.FAILED,
                scheduled_ac_charge_loop_res=ScheduledACChargeLoopResParams(),
            ),
            Namespace.ISO_V20_AC,
            ISOV20PayloadTypes.AC_MAINSTREAM,
        ),
        # DCChargeLoopReq:
        # TODO Need to add DC messages for ISO 15118-20
        #     None,
        # WPTChargeLoopReq:
        # TODO Need to add WPT messages for ISO 15118-20
        #     None,
        MeteringConfirmationReq: (
            MeteringConfirmationRes(
                header=header, response_code=ResponseCodeV20.FAILED
            ),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
        # DCWeldingDetectionReq:
        # TODO Need to add DC messages for ISO 15118-20
        #     None,
        # VehicleCheckInReq:
        # TODO Need to add messages for ISO 15118-20
        #     None,
        # VehicleCheckOutReq:
        # TODO Need to add messages for ISO 15118-20
        #     None,
        SessionStopReqV20: (
            SessionStopResV20(header=header, response_code=ResponseCodeV20.FAILED),
            Namespace.ISO_V20_COMMON_MSG,
            ISOV20PayloadTypes.MAINSTREAM,
        ),
    }

    return failed_response_iso_v20
