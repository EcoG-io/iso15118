"""Tests for the iso15118 security module."""
from iso15118.shared.security import (
    all_certificates_from_chain,
    certificate_to_pem_string,
    derive_certificate_hash_data,
    get_certificate_hash_data,
)
from tests.sample_certs.load_certs import (
    load_certificate_chain,
    load_contract_certificate,
    load_root_certificate,
    load_sub_ca_2_certificate,
)


def test_derive_certificate_hash_data_root_certificate() -> None:
    """Test that correct certificate hash data is extracted."""
    certificate_bytes = load_root_certificate()

    # A root certificate will be self-signed.
    hash_data = derive_certificate_hash_data(certificate_bytes, certificate_bytes)

    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": "z4Yn1aMMr-YdbGaRcRFFT_qBHdaYSZdQd0586M-3HHE=",
        "issuer_key_hash": "S4UASAPa4rzDIgjp2i6pLvhzBOUyh9TGIvJeE-qTLPQ=",
        "serial_number": "11",
        "responder_url": "https://www.example.com/",
    }


def test_derive_certificate_hash_data_contract_certificate() -> None:
    """Test that correct certificate data is extracted for a contract certificate."""
    hash_data = derive_certificate_hash_data(
        load_contract_certificate(),
        load_sub_ca_2_certificate(),
    )

    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": "BQ5EPsVHvmz-iy5lfQkL4H2GonQAuyb79KJfy-shZTQ=",
        "issuer_key_hash": "Xre37wLCZB7m4TflmE1DcRbucyVyN0BQTRdYR6buWgA=",
        "serial_number": "15",
        "responder_url": "https://www.example.com/",
    }


def test_certificate_to_pem_string() -> None:
    """Test that a certificate is correctly loaded into PEM format."""
    certificate_bytes = load_contract_certificate()
    pem_string = certificate_to_pem_string(certificate_bytes)
    # Asserting that the whole PEM string is equal to some blob of text is not
    # very informative, so we just check the PEM format and a small part of the string.
    # It's unlikely that any reasonable implementation of certificate_to_pem_string
    # will violate this.
    assert pem_string.startswith("-----BEGIN CERTIFICATE-----\nMIIB3jCCAYSg")
    assert "-----END CERTIFICATE-----" in pem_string


def test_all_certificates_from_chain_with_root_cert():
    """Test that certificates are taken from the chain in the right order."""
    cert_chain = load_certificate_chain()
    root_cert = load_root_certificate()

    expected_cert_list = [
        cert_chain.certificate,
        cert_chain.sub_certificates.certificates[0],
        cert_chain.sub_certificates.certificates[1],
        root_cert,
    ]

    assert all_certificates_from_chain(cert_chain, root_cert) == expected_cert_list


def test_all_certs_from_chain_no_root_cert():
    """Test that certificates are taken from the chain in the right order."""
    cert_chain = load_certificate_chain()
    root_cert = None

    expected_cert_list = [
        cert_chain.certificate,
        cert_chain.sub_certificates.certificates[0],
        cert_chain.sub_certificates.certificates[1],
    ]

    assert all_certificates_from_chain(cert_chain, root_cert) == expected_cert_list


def test_get_certificate_hash_data():
    cert_chain = load_certificate_chain()
    root_cert = load_root_certificate()
    hash_data = get_certificate_hash_data(cert_chain, root_cert)

    assert hash_data == [
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "BQ5EPsVHvmz-iy5lfQkL4H2GonQAuyb79KJfy-shZTQ=",
            "issuer_key_hash": "Xre37wLCZB7m4TflmE1DcRbucyVyN0BQTRdYR6buWgA=",
            "serial_number": "15",
            "responder_url": "https://www.example.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "btnbzKuhBDrHRQx10P_aItU5RBDQtOcxmI_i08ntkVs=",
            "issuer_key_hash": "CyRfoEzBwIG-hQAUZeE0KZw8tCzMYSiMgDlRy3m3Cxk=",
            "serial_number": "13",
            "responder_url": "https://www.example.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "z4Yn1aMMr-YdbGaRcRFFT_qBHdaYSZdQd0586M-3HHE=",
            "issuer_key_hash": "S4UASAPa4rzDIgjp2i6pLvhzBOUyh9TGIvJeE-qTLPQ=",
            "serial_number": "12",
            "responder_url": "https://www.example.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "z4Yn1aMMr-YdbGaRcRFFT_qBHdaYSZdQd0586M-3HHE=",
            "issuer_key_hash": "S4UASAPa4rzDIgjp2i6pLvhzBOUyh9TGIvJeE-qTLPQ=",
            "serial_number": "11",
            "responder_url": "https://www.example.com/",
        },
    ]


def test_get_certificate_hash_data_no_chain():
    """Test that get_certificate_hash_data returns None with no chain."""
    cert_chain = None
    root_cert = load_root_certificate()
    hash_data = get_certificate_hash_data(cert_chain, root_cert)
    assert hash_data is None


def test_get_certificate_hash_data_no_root():
    """Test that get_certificate_hash_data returns None with no root cert."""
    cert_chain = load_certificate_chain()
    root_cert = None
    hash_data = get_certificate_hash_data(cert_chain, root_cert)
    assert hash_data is None
