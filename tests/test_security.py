"""Tests for the iso15118 security module."""
import pytest
from cryptography.x509 import ExtensionNotFound

from iso15118.shared.security import (
    all_certificates_from_chain,
    certificate_to_pem_string,
    derive_certificate_hash_data,
    get_certificate_hash_data,
)
from tests.sample_certs.load_certs import (
    load_certificate_chain,
    load_contract_certificate,
    load_no_ocsp_root_certificate,
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
        "issuer_name_hash": "nYwcUlDO5yz8nuq_z8h5WhCkhcQA5RCWds-otYxz92g=",
        "issuer_key_hash": "Jrz-QyKqpYx94HmEHgGCiFuTA_nC_34X9XufAQwWAsI=",
        "serial_number": "12353",
        "responder_url": "http://ca.myown.com/",
    }


def test_no_hash_data_with_no_ocsp() -> None:
    """Tests no hash data is derived without OCSP data"""
    # An ExtensionNotFound is raised in this case,
    # because the field "Authority Information Access"
    # does not exist in the Certificate
    certificate_bytes = load_no_ocsp_root_certificate()

    with pytest.raises(ExtensionNotFound):
        derive_certificate_hash_data(certificate_bytes, certificate_bytes)


def test_derive_certificate_hash_data_contract_certificate() -> None:
    """Test that correct certificate data is extracted for a contract certificate."""
    hash_data = derive_certificate_hash_data(
        load_contract_certificate(),
        load_sub_ca_2_certificate(),
    )

    assert hash_data == {
        "hash_algorithm": "SHA256",
        "issuer_name_hash": "ZycWQ1dc_5ZgLYpfcQPBFfiSwfH925lgYXu_ZmpDuWg=",
        "issuer_key_hash": "a7mphV66rCFJ5YoOqhReENHt78yrJzxitGxerv-FU54=",
        "serial_number": "12356",
        "responder_url": "http://ca.myown.com/",
    }


def test_certificate_to_pem_string() -> None:
    """Test that a certificate is correctly loaded into PEM format."""
    certificate_bytes = load_contract_certificate()
    pem_string = certificate_to_pem_string(certificate_bytes)
    # Asserting that the whole PEM string is equal to some blob of text is not
    # very informative, so we just check the PEM format and a small part of the string.
    # It's unlikely that any reasonable implementation of certificate_to_pem_string
    # will violate this.
    assert pem_string.startswith("-----BEGIN CERTIFICATE-----\nMIICSTCCAfCg")
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
            "issuer_name_hash": "ZycWQ1dc_5ZgLYpfcQPBFfiSwfH925lgYXu_ZmpDuWg=",
            "issuer_key_hash": "a7mphV66rCFJ5YoOqhReENHt78yrJzxitGxerv-FU54=",
            "serial_number": "12356",
            "responder_url": "http://ca.myown.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "EmoLeXDvkq6gXNIj6788YfEhtuBM6JY-ftm44q3LZrs=",
            "issuer_key_hash": "kEWx6E4JL3N6pYWk0R2LpvRnyXhu5uF2Xg9mH1OtdLI=",
            "serial_number": "12355",
            "responder_url": "http://ca.myown.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "nYwcUlDO5yz8nuq_z8h5WhCkhcQA5RCWds-otYxz92g=",
            "issuer_key_hash": "Jrz-QyKqpYx94HmEHgGCiFuTA_nC_34X9XufAQwWAsI=",
            "serial_number": "12354",
            "responder_url": "http://ca.myown.com/",
        },
        {
            "hash_algorithm": "SHA256",
            "issuer_name_hash": "nYwcUlDO5yz8nuq_z8h5WhCkhcQA5RCWds-otYxz92g=",
            "issuer_key_hash": "Jrz-QyKqpYx94HmEHgGCiFuTA_nC_34X9XufAQwWAsI=",
            "serial_number": "12353",
            "responder_url": "http://ca.myown.com/",
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
