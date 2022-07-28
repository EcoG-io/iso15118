"""Tests for the iso15118 security module."""
from pathlib import Path

from iso15118.shared.security import (
    certificate_to_pem_string,
    derive_certificate_hash_data,
)


def test_derive_certificate_hash_data_root_certificate() -> None:
    """Test that correct certificate hash data is extracted."""
    certificate_path = Path(__file__).parent / "sample_certs" / "moRootCACert.der"
    with open(certificate_path, "rb") as f:
        certificate_bytes = f.read()
    hash_data = derive_certificate_hash_data(certificate_bytes)
    # This hash data was derived by using the OCSPRequestBuilder.
    # This isn't used in the code because it requires the issuer certificate,
    # which we may not always have in practice (the root certificate may be absent).
    # Still, we will have enough information to populate this hash data.
    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": b"\xcf\x86'\xd5\xa3\x0c\xaf\xe6\x1dlf\x91q\x11EO\xfa\x81\x1d\xd6\x98I\x97PwN|\xe8\xcf\xb7\x1cq",  # noqa: E501
        "issuer_key_hash": b'K\x85\x00H\x03\xda\xe2\xbc\xc3"\x08\xe9\xda.\xa9.\xf8s\x04\xe52\x87\xd4\xc6"\xf2^\x13\xea\x93,\xf4',  # noqa: E501
        "serial_number": 11,
        "responder_url": "https://www.example.com/",
    }


def test_derive_certificate_hash_data_contract_certificate() -> None:
    """Test that correct certificate data is extracted for a contract certificate."""
    certificate_path = Path(__file__).parent / "sample_certs" / "contractLeafCert.der"
    with open(certificate_path, "rb") as f:
        certificate_bytes = f.read()
    hash_data = derive_certificate_hash_data(certificate_bytes)
    # This hash data was derived by using the OCSPRequestBuilder.
    # This isn't used in the code because it requires the issuer certificate,
    # which we may not always have in practice (the root certificate may be absent).
    # Still, we will have enough information to populate this hash data.
    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": b"\x05\x0eD>\xc5G\xbel\xfe\x8b.e}\t\x0b\xe0}\x86\xa2t\x00\xbb&\xfb\xf4\xa2_\xcb\xeb!e4",  # noqa: E501
        "issuer_key_hash": b"\xb3|\xf7\xca<\x05\xb7\xfe5\xf4\x86\xc3-A\xcb\x86O.R\xec&I\xcf\x17\x91x%\xaf\x8a\xda-`",  # noqa: E501
        "serial_number": 15,
        "responder_url": "https://www.example.com/",
    }


def test_certificate_to_pem_string() -> None:
    """Test that a certificate is correctly loaded into PEM format."""
    certificate_path = Path(__file__).parent / "sample_certs" / "contractLeafCert.der"
    with open(certificate_path, "rb") as f:
        certificate_bytes = f.read()
    pem_string = certificate_to_pem_string(certificate_bytes)
    # Asserting that the whole PEM string is equal to some blob of text is not
    # very informative, so we just check the PEM format and a small part of the string.
    # It's unlikely that any reasonable implementation of certificate_to_pem_string
    # will violate this.
    assert pem_string.startswith("-----BEGIN CERTIFICATE-----\nMIIB3jCCAYSg")
    assert "-----END CERTIFICATE-----" in pem_string
