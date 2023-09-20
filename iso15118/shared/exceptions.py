from typing import Any, Union

from iso15118.shared.messages.din_spec.datatypes import ResponseCode as ResponseCodeDIN
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)


class InvalidInterfaceError(Exception):
    """
    This error is raised when the specified interface is not found under the
    available list of interfaces or a link-local address is not associated with
    it
    """


class NoLinkLocalAddressError(Exception):
    """
    Is thrown if no IPv6 link-local address can be found. Used by TCP/TLS
    client and server
    """


class MACAddressNotFound(Exception):
    """
    Is thrown if it was not possible to identify the MAC Address of the NIC
    """


class InvalidMessageError(Exception):
    """
    Is thrown when validating whether or not an incoming message is a valid
    SupportedAppProtocolReq, SupportedAppProtocolRes, ISO 15118-2 message, or
    ISO 15118-20 message and whether or not the session ID is correct (in case
    of a V2GMessage). See is_message_valid() function of a State.
    """


class InvalidV2GTPMessageError(Exception):
    """Is thrown when trying to create a V2GTP message from a bytes object"""


class InvalidSDPRequestError(Exception):
    """Is thrown when trying to create an SDP request from a bytearray"""


class InvalidSDPResponseError(Exception):
    """Is thrown when trying to create an SDP response from a bytearray"""


class SDPFailedError(Exception):
    """
    Is thrown when the SECC Discovery Protocol (SDP) failed despite running
    through all configured SDP retry cycles (see evcc_settings.py)
    """


class MessageProcessingError(Exception):
    """
    Is thrown when parsing an incoming request (SECC) or response (EVCC)
    and the incoming message cannot be processed successfully.
    The message_name argument for the __init__ is the name of the message that
    caused the processing error.
    """

    def __init__(self, message_name: str):
        Exception.__init__(self)
        self.message_name = message_name


class FaultyStateImplementationError(Exception):
    """
    Is thrown when the fields in a state are not set as expected after
    processing an incoming message. The 'error' field provides additional
    information as to what specifically is wrong.
    """


class InvalidPayloadTypeError(Exception):
    """Is thrown when trying to instantiate a V2GTPMessage object with a
    payload type that is not supported by ISO 15118 version of a running
    communication session
    """


class InvalidProtocolError(Exception):
    """
    Is thrown when providing a protocol that is not a member of the
    Protocol enum
    """


class EXIEncodingError(Exception):
    """Is thrown when trying to serialise anobject into an EXI byte stream"""


class EXIDecodingError(Exception):
    """Is thrown when trying to EXI decode an incoming byte stream"""


class InvalidSettingsValueError(Exception):
    """
    Is thrown when a setting is read and the value is invalid.
    The 'entity' field provides information whether it's the EVCC, SECC, or
    shared settings.
    """

    def __init__(self, entity: str, setting: str, invalid_value: Any):
        Exception.__init__(self)
        self.entity = entity
        self.setting = setting
        self.invalid_value = invalid_value


class CertSignatureError(Exception):
    """
    Is thrown if the verification of a certificate's signature fails.
    The 'subject' field informs about the subject attribute of the certificate
    who's signature verification failed. The 'issuer' field informs about the
    issuer attribute, pointing towards the issuer certificate that was used to
    verify the signature. The extra_info field provides more debugging
    information.

    If several certificates in a certificate chain are checked, then this
    exception is thrown for the first certificate that causes the error.
    """

    def __init__(self, subject: str, issuer: str, extra_info: str = ""):
        Exception.__init__(self)
        self.subject = subject
        self.issuer = issuer
        self.extra_info = extra_info


class CertNotYetValidError(Exception):
    """
    Is thrown if a certificate is not yet valid.
    The 'subject' field informs about the subject attribute of the certificate
    that is not yet valid.

    If several certificates in a certificate chain are checked, then this
    exception is thrown for the first certificate that causes the error.
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertExpiredError(Exception):
    """
    Is thrown if a certificate is expired.
    The 'subject' field informs about the subject attribute of the certificate
    that is expired.

    If several certificates in a certificate chain are checked, then this
    exception is thrown for the first certificate that causes the error.
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertRevokedError(Exception):
    """
    Is thrown if a certificate is revoked.
    The 'subject' field informs about the subject attribute of the certificate
    that is revoked.

    If several certificates in a certificate chain are checked, then this
    exception is thrown for the first certificate that causes the error.
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertAttributeError(Exception):
    """
    Is thrown if an attribute of the certificate is not matching the expected
    value. The 'subject' field informs about the subject attribute of the
    certificate whose attribute check failed. The fields 'attr_name' and
    'invalid_value' provide more information about the failed attribute check.

    If several certificates in a certificate chain are checked, then this
    exception is thrown for the first certificate that causes the error.
    """

    def __init__(self, subject: str, attr: str, invalid_value: str):
        Exception.__init__(self)
        self.subject = subject
        self.attr = attr
        self.invalid_value = invalid_value


class CertChainLengthError(Exception):
    """Is thrown if more sub-CA certificates are provided than allowed"""

    def __init__(self, allowed_num_sub_cas: int, num_sub_cas: int):
        Exception.__init__(self)
        self.allowed_num_sub_cas = allowed_num_sub_cas
        self.num_sub_cas = num_sub_cas


class EncryptionError(Exception):
    """Is thrown when an error occurs while trying to encrypt a private key"""


class DecryptionError(Exception):
    """Is thrown when an error occurs while trying to decrypt a private key"""


class KeyTypeError(Exception):
    """Is thrown when loading a private key whose type is not recognised"""


class PrivateKeyReadError(Exception):
    """Is thrown when an error occurs while trying to load a private key"""


class NoSupportedProtocols(Exception):
    """Is thrown when no supported protocols are configured"""


class NoSupportedEnergyServices(Exception):
    """Is thrown when no supported energy services are configured"""


class NoSupportedAuthenticationModes(Exception):
    """Is thrown when no supported authentication modes are configured"""


class OCSPServerNotFoundError(Exception):
    """Is thrown when no OCSP server entry is found.

    The Authority Information Access extension field may not contain any OCSP
    server entries.  If so, this exception is raised.
    """

    def __init__(self):
        Exception.__init__(
            self,
            "No OCSP server entry in Authority Information Access extension field.",
        )


class V2GMessageValidationError(Exception):
    """Is thrown if message validation is failed"""

    def __init__(
        self,
        reason: str,
        response_code: Union[ResponseCode, ResponseCodeV20, ResponseCodeDIN],
        message: Any,
    ):
        Exception.__init__(self)
        self.reason = reason
        self.response_code = response_code
        self.message = message
