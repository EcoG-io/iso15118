import base64
import json
import logging
from base64 import b64decode, b64encode
from typing import Union

from pydantic import ValidationError

from iso15118.shared.settings import MESSAGE_LOG_JSON, MESSAGE_LOG_EXI
from iso15118.shared.exceptions import EXIDecodingError, EXIEncodingError
from iso15118.shared.exificient_wrapper import ExiCodec
from iso15118.shared.messages import BaseModel
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.enums import Namespace
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq as AuthorizationReqV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationRes,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    CertificateInstallationRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    SessionSetupReq,
    SessionSetupRes,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.xmldsig import SignedInfo

logger = logging.getLogger(__name__)
exi_codec = ExiCodec()


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to allow the encoding of raw bytes to Base64 encoded
    strings to conform with their XSD type base64Binary. Also, JSON cannot
    encode bytes by default, so the base64Binary type comes in handy.
    """

    # pylint: disable=method-hidden
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


class CustomJSONDecoder(json.JSONDecoder):
    """
    Custom JSON decoder to allow the decoding of Base64 encoded bytes back to
    raw bytes.

    We use a custom object_hook() function for json.JSONDecoder to match the
    corresponding ISO 15118 message and datatype fields that we know have a
    bytes value and are serialised as Base64 encoded (base64_encoded_fields_set)
    and then decode each matching dict entry from Base64 back to raw bytes.
    """

    base64_encoded_fields_set = {
        "Certificate",
        "DHPublicKey",
        "GenChallenge",
        "MeterSignature",
        "OEMProvisioningCert",
        "SECP521_EncryptedPrivateKey",
        "SigMeterReading",
        "TPM_EncryptedPrivateKey",
        "Value",
        "value",
        "X448_EncryptedPrivateKey",
        "DigestValue",
    }

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct) -> dict:
        for field in self.base64_encoded_fields_set.intersection(set(dct)):
            # 'Value' (or 'value') can be an integer field in the pydantic model
            # PhysicalValue (ISO 15118-2) and RationalNumber (ISO 15118-20) and
            # a string in EMAID. But it can also be a bytes field in the
            # pydantic model EncryptedPrivateKey. So we need to make sure to
            # only Base64 decode the one that is for sure not of type integer
            # or string. But for the string case, we need to distinguish
            # between a Base64 encoded string and a normal string (like the
            # one in EMAID).
            # TODO Need to find a better way, feels more and more like a hack
            if field in ("Value", "value") and isinstance(dct[field], int):
                continue

            if field in ("Value", "value") and isinstance(dct[field], str):
                # Trying to distinguish and EMAID value string from an
                # EncryptedPrivateKey value string. The latter is Base64
                # encoded. An EMAID is 14 or 15 characters long, a Base64
                # encoded EncryptedPrivateKey is definitely bigger.
                # Feels like a hack, is a hack, but what else shall we do ...?
                if len(dct[field]) <= 15:
                    continue

            dct[field] = b64decode(dct[field])
        return dct


def to_exi(msg_element: BaseModel, protocol_ns: str) -> bytes:
    """
    Encodes the message into a bytes stream using the EXI codec

    Args:
        msg_element: The V2G message (or message element) to be EXI encoded
        protocol_ns: The protocol namespace that uniquely identifies the XSD
                     schema, which the EXI encoder needs to use for the encoding
                     process

    Returns:
        A bytes object, representing the EXI encoded message
    """
    msg_to_dct: dict = msg_element.dict(by_alias=True, exclude_none=True)
    try:
        # Pydantic does not export the name of the model itself to a dict,
        # so we need to add it (the message names like 'SessionSetupReq')
        if (
            str(msg_element) == "CertificateChain"
            and protocol_ns == Namespace.ISO_V2_MSG_DEF
        ):
            # In case of CertificateInstallationRes and CertificateUpdateRes,
            # str(message) would not be 'ContractSignatureCertChain' but
            # 'CertificateChain' (the type of ContractSignatureCertChain)
            message_dict = {"ContractSignatureCertChain": msg_to_dct}
        elif str(msg_element) == "CertificateChain" and protocol_ns.startswith(
            Namespace.ISO_V20_BASE
        ):
            # In case of CertificateInstallationRes,
            # str(message) would not be 'CPSCertificateChain' but
            # 'CertificateChain' (the type of CPSCertificateChain)
            message_dict = {"CPSCertificateChain": msg_to_dct}
        elif str(msg_element) == "SignedCertificateChain":
            # In case of CertificateInstallationReq,
            # str(message) would not be 'OEMProvisioningCertificateChain' but
            # 'SignedCertificateChain' (the type of OEMProvisioningCertificateChain)
            message_dict = {"OEMProvisioningCertificateChain": msg_to_dct}
        elif isinstance(msg_element, V2GMessageV2):
            # TODO Add support for DIN SPEC 70121
            message_dict = {"V2G_Message": msg_to_dct}
        else:
            message_dict = {str(msg_element): msg_to_dct}

        msg_content = json.dumps(message_dict, cls=CustomJSONEncoder)
    except Exception as exc:
        raise EXIEncodingError(
            f"EXIEncodingError for {str(msg_element)}: \
                               {exc}"
        ) from exc

    if MESSAGE_LOG_JSON:
        logger.debug(
            f"Message to encode: \n{msg_content} " f"\nXSD namespace: {protocol_ns}"
        )

    try:
        if isinstance(msg_element, SignedInfo):
            exi_stream = exi_codec.encode_signed_info(msg_content)
        else:
            exi_stream = exi_codec.encode(msg_content, protocol_ns)
    except Exception as exc:
        logger.error(f"EXIEncodingError for {str(msg_element)}: {exc}")
        raise EXIEncodingError(
            f"EXIEncodingError for {str(msg_element)}: " f"{exc}"
        ) from exc

    if MESSAGE_LOG_EXI:
        logger.debug(f"EXI-encoded message: \n{exi_stream.hex()}")
        logger.debug(
            "EXI-encoded message (Base64):" f"\n{base64.b64encode(exi_stream).hex()}"
        )

    return exi_stream


def from_exi(
    exi_message: bytes, namespace: str
) -> Union[
    SupportedAppProtocolReq, SupportedAppProtocolRes, V2GMessageV2, V2GMessageV20
]:
    """
    Decodes the EXI encoded bytearray into a message according to the payload
    type provided.

    Args:
        exi_message: The EXI-encoded message, given as a bytes stream
        namespace: The XSD namespace used to encode that message, so
                  we know how to de-serialise the decoded message

    Raises:
        EXIDecodingError
    """
    if MESSAGE_LOG_EXI:
        logger.debug(
            f"EXI-encoded message: \n{exi_message.hex()}"
            f"\n XSD namespace: {namespace}"
        )
        logger.debug(
            "EXI-encoded message (Base64):" f"\n{base64.b64encode(exi_message).hex()}"
        )

    try:
        decoded_dict = json.loads(
            exi_codec.decode(exi_message, namespace), cls=CustomJSONDecoder
        )
    except Exception as exc:
        raise EXIDecodingError(f"EXIDecodingError: {exc}") from exc

    if MESSAGE_LOG_JSON:
        logger.debug(
            f"Decoded message: \n{decoded_dict}" f"\nXSD namespace: {namespace}"
        )

    try:
        if namespace == Namespace.SAP and "supportedAppProtocolReq" in decoded_dict:
            return SupportedAppProtocolReq.parse_obj(
                decoded_dict["supportedAppProtocolReq"]
            )

        if namespace == Namespace.SAP and "supportedAppProtocolRes" in decoded_dict:
            return SupportedAppProtocolRes.parse_obj(
                decoded_dict["supportedAppProtocolRes"]
            )

        if namespace == Namespace.ISO_V2_MSG_DEF:
            return V2GMessageV2.parse_obj(decoded_dict["V2G_Message"])

        if namespace.startswith("urn:iso:std:iso:15118:-20"):
            # The message name is the first key of the dict
            msg_name = next(iter(decoded_dict))
            # When parsing the dict, we need to remove the first key, which is
            # the message name itself (e.g. SessionSetupReq)
            msg_dict = decoded_dict[msg_name]
            msg_classes_dict = {
                "SessionSetupReq": SessionSetupReq,
                "SessionSetupRes": SessionSetupRes,
                "AuthorizationSetupReq": AuthorizationSetupReq,
                "AuthorizationSetupRes": AuthorizationSetupRes,
                "AuthorizationReq": AuthorizationReqV20,
                "AuthorizationRes": AuthorizationRes,
                "ServiceDiscoveryReq": ServiceDiscoveryReq,
                "ServiceDiscoveryRes": ServiceDiscoveryRes,
                "CertificateInstallationReq": CertificateInstallationReq,
                "CertificateInstallationRes": CertificateInstallationRes,
                # TODO add all the other message types and states
            }
            msg_class = msg_classes_dict.get(msg_name)
            if not msg_class:
                logger.error(
                    "Unable to identify message to parse given the message "
                    f"name {msg_name}"
                )
                raise EXIDecodingError(f"Unable to decode {msg_name}")

            return msg_class.parse_obj(msg_dict)

        # TODO Add support for DIN SPEC 70121

        raise EXIDecodingError(
            "EXI decoding error: can't identify protocol to " "use for decoding"
        )
    except ValidationError as exc:
        raise EXIDecodingError(
            f"EXI decoding error: {exc}. \n\nDecoded dict: " f"{decoded_dict}"
        ) from exc
