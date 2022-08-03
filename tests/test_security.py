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

    # A root certificate will be self_signed.
    hash_data = derive_certificate_hash_data(certificate_bytes, certificate_bytes)

    # This hash data was derived by using the OCSPRequestBuilder.
    # This isn't used in the code because it requires the issuer certificate,
    # which we may not always have in practice (the root certificate may be absent).
    # Still, we will have enough information to populate this hash data.
    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": "z4Yn1aMMr-YdbGaRcRFFT_qBHdaYSZdQd0586M-3HHE=",  # noqa: E501
        "issuer_key_hash": "S4UASAPa4rzDIgjp2i6pLvhzBOUyh9TGIvJeE-qTLPQ=",  # noqa: E501
        "serial_number": "11",
        "responder_url": "https://www.example.com/",
    }


def test_derive_certificate_hash_data_contract_certificate() -> None:
    """Test that correct certificate data is extracted for a contract certificate."""
    cert_dir = Path(__file__).parent / "sample_certs"
    contract_certificate_path = cert_dir / "contractLeafCert.der"
    sub_ca_2_certificate_path = cert_dir / "moSubCA2Cert.der"
    with open(contract_certificate_path, "rb") as contract_cert_file:
        contract_certificate_bytes = contract_cert_file.read()
    with open(sub_ca_2_certificate_path, "rb") as ca_2_cert_file:
        sub_ca_2_certificate_bytes = ca_2_cert_file.read()
    hash_data = derive_certificate_hash_data(
        contract_certificate_bytes,
        sub_ca_2_certificate_bytes,
    )
    # This hash data was derived by using the OCSPRequestBuilder.
    # This isn't used in the code because it requires the issuer certificate,
    # which we may not always have in practice (the root certificate may be absent).
    # Still, we will have enough information to populate this hash data.
    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": "BQ5EPsVHvmz-iy5lfQkL4H2GonQAuyb79KJfy-shZTQ=",  # noqa: E501
        "issuer_key_hash": "Xre37wLCZB7m4TflmE1DcRbucyVyN0BQTRdYR6buWgA=",  # noqa: E501
        "serial_number": "15",
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
