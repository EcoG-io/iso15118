from pathlib import Path
from typing import Optional

from iso15118.shared.messages.iso15118_2.datatypes import (
    Certificate,
    CertificateChain,
    SubCertificates,
)


def load_certificate_chain(contract: Optional[str] = None) -> CertificateChain:
    """Load the sample certificate chain.

    This includes the contract, sub-CA 2, and sub-CA 1 certificates.

    Returns:
        The sample certificate chain, with certificates in DER (binary) form.
    """
    return CertificateChain(
        certificate=load_contract_certificate(contract),
        sub_certificates=SubCertificates(
            certificates=[load_sub_ca_2_certificate(), load_sub_ca_1_certificate()],
        ),
    )


def get_cert_dir() -> Path:
    """Get the directory containing sample certificates."""
    return Path(__file__).parent


def load_root_certificate() -> Certificate:
    """Load the sample root certificate.

    Returns:
        The sample root certificate in DER (binary) form.
    """
    cert_dir = get_cert_dir()
    with open(cert_dir / "moRootCACert.der", "rb") as root_file:
        root_certificate = root_file.read()

    return root_certificate


def load_no_ocsp_root_certificate() -> Certificate:
    """Load the sample root certificate.

    Returns:
        The sample root certificate in DER (binary) form.
    """
    cert_dir = get_cert_dir()
    with open(cert_dir / "moRootCACert_no_ocsp.der", "rb") as root_file:
        root_certificate = root_file.read()

    return root_certificate


def load_sub_ca_1_certificate() -> Certificate:
    """Load the sample sub-CA 1 certificate.

    Returns:
        The sample sub-CA 1 certificate in DER (binary) form.
    """
    cert_dir = get_cert_dir()
    with open(cert_dir / "moSubCA1Cert.der", "rb") as root_file:
        sub_ca_1_certificate = root_file.read()

    return sub_ca_1_certificate


def load_sub_ca_2_certificate() -> Certificate:
    """Load the sample sub-CA 2 certificate.

    Returns:
        The sample sub-CA 2 certificate in DER (binary) form.
    """
    cert_dir = get_cert_dir()
    with open(cert_dir / "moSubCA2Cert.der", "rb") as root_file:
        sub_ca_2_certificate = root_file.read()

    return sub_ca_2_certificate


def load_contract_certificate(contract_path: Optional[str] = None) -> Certificate:
    """Load the sample contract certificate.

    Returns:
        The sample contract certificate in DER (binary) form.
    """

    if contract_path is None:
        cert_dir = get_cert_dir()
        path = f"{cert_dir}/contractLeafCert.der"
    else:
        path = contract_path

    with open(path, "rb") as root_file:
        contract_certificate = root_file.read()

    return contract_certificate
