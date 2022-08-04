from pathlib import Path

from iso15118.shared.messages.iso15118_2.datatypes import (
    Certificate,
    CertificateChain,
    SubCertificates,
)


def load_certificate_chain() -> CertificateChain:
    """Load the sample certificate chain.

    This includes the contract, sub-CA 2, and sub-CA 1 certificates.

    Returns:
        The sample certificate chain, with certificates in DER (binary) form.
    """
    cert_dir = Path(__file__).parent
    with open(cert_dir / "contractLeafCert.der", "rb") as leaf_file:
        leaf_certificate = leaf_file.read()
    with open(cert_dir / "moSubCA1Cert.der", "rb") as sub_ca_1_file:
        sub_ca_1_certificate = sub_ca_1_file.read()
    with open(cert_dir / "moSubCA2Cert.der", "rb") as sub_ca_2_file:
        sub_ca_2_certificate = sub_ca_2_file.read()

    return CertificateChain(
        certificate=leaf_certificate,
        sub_certificates=SubCertificates(
            certificates=[sub_ca_2_certificate, sub_ca_1_certificate],
        ),
    )


def load_root_certificate() -> Certificate:
    """Load the sample root certificate.

    Returns:
        The sample root certificate in DER (binary) form.
    """
    cert_dir = Path(__file__).parent
    with open(cert_dir / "moRootCACert.der", "rb") as root_file:
        root_certificate = root_file.read()

    return root_certificate
