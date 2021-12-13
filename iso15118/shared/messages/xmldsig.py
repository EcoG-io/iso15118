from typing import List

from pydantic import Field

from iso15118.shared.messages import BaseModel


class TransformDetails(BaseModel):
    algorithm: str = Field(..., alias="Algorithm")


class Transform(BaseModel):
    details: List[TransformDetails] = Field(..., alias="Transform")


class DigestMethod(BaseModel):
    algorithm: str = Field(..., alias="Algorithm")


class SignatureMethod(BaseModel):
    algorithm: str = Field(..., alias="Algorithm")


class CanonicalizationMethod(BaseModel):
    algorithm: str = Field(..., alias="Algorithm")


# TODO: Question for Marc: Reference in xmldisg-core-schema has the following Schema
# <attribute name="Id" type="ID" use="optional"/>
#   <attribute name="URI" type="anyURI" use="optional"/>
#   <attribute name="Type" type="anyURI" use="optional"/>
# where the attributes are optional. why not all of them were included and the one it was,
# is mandatory?
class Reference(BaseModel):
    transforms: Transform = Field(..., alias="Transforms")
    digest_method: DigestMethod = Field(..., alias="DigestMethod")
    digest_value: bytes = Field(..., alias="DigestValue")
    # 'URI' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    uri: str = Field(..., alias="URI")


class SignedInfo(BaseModel):
    canonicalization_method: CanonicalizationMethod = Field(
        ..., alias="CanonicalizationMethod"
    )
    signature_method: SignatureMethod = Field(..., alias="SignatureMethod")
    reference: List[Reference] = Field(..., max_items=4, alias="Reference")

    def __str__(self):
        return type(self).__name__


class SignatureValue(BaseModel):
    value: bytes = Field(..., alias="value")


class Signature(BaseModel):
    signed_info: SignedInfo = Field(..., alias="SignedInfo")
    signature_value: SignatureValue = Field(..., alias="SignatureValue")


class X509IssuerSerial(BaseModel):
    x509_issuer_name: str = Field(..., alias="X509IssuerName")
    x509_serial_number: int = Field(..., alias="X509SerialNumber")


class SignedElement(BaseModel):
    """
    The element of a BodyBase (the message inside the Body element of a
    V2GMessage) that needs to be digitally signed and referenced in the
    SignedInfo field of the header.

    Example:
    For the AuthorizationReq it's the complete message.
    For the CertificateInstallationRes, it's four elements of the message, not
    the complete message.
    """
