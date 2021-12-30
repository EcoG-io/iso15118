"""
DataTypes for the construction of the XML signature syntax
Please check:
Section 7.9.2.4.2 XML Signature mechanism from ISO 15118-2
https://en.wikipedia.org/wiki/XML_Signature
https://www.w3.org/TR/xmldsig-core1/
"""

from typing import List

from pydantic import Field, HttpUrl

from iso15118.shared.messages import BaseModel


class Transform(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class Transforms(BaseModel):
    # TODO: Q for Marc: according to requirement [V2G2-767], The maximum number of
    #       Transforms is limited to one (1) (i.e. per referenced element where a
    #       signature is to be transmitted for, just one single Transform algorithm can be indicated).
    #       shouldnt we then limit the elements to 1?
    transform: List[Transform] = Field(..., alias="Transform")


class DigestMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class SignatureMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class CanonicalizationMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


# TODO: Question for Marc: Reference in xmldisg-core-schema has the following Schema
#       <attribute name="Id" type="ID" use="optional"/>
#       <attribute name="URI" type="anyURI" use="optional"/>
#       <attribute name="Type" type="anyURI" use="optional"/>
#       where the attributes are optional. why not all of them were included and the one it was,
#       is mandatory?
class Reference(BaseModel):
    transforms: Transforms = Field(..., alias="Transforms")
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
    # TODO: According to the schema, Reference is unbounded, but here
    #       a limit of 4 entries is enforced. Does that come from a requirement?
    #       Couldnt find any...
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
