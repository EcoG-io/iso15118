import logging
import os

import pytest

from iso15118.secc import Config
from iso15118.shared.messages.enums import AuthEnum, Protocol
from iso15118.shared.security import CertPath
from iso15118.shared.settings import SettingKey, shared_settings
from iso15118.shared.utils import (
    load_requested_auth_modes,
    load_requested_protocols,
)


class TestSECCConfig:
    @pytest.fixture(autouse=True)
    def setup_config(self):
        shared_settings[SettingKey.PKI_PATH] = "/pki_path"
        shared_settings[SettingKey.MESSAGE_LOG_EXI] = True
        shared_settings[SettingKey.MESSAGE_LOG_JSON] = True
        self.config = Config(
            iface="eth0",
            log_level=logging.DEBUG,
            enforce_tls=False,
            free_charging_service=False,
            free_cert_install_service=True,
            allow_cert_install_service=True,
            use_cpo_backend=False,
            supported_protocols=load_requested_protocols(
                ["ISO_15118_2", "DIN_SPEC_70121"]
            ),
            supported_auth_options=load_requested_auth_modes(["EIM"]),
            standby_allowed=False,
        )

    @pytest.mark.parametrize(
        "config_name, new_value, expected_value",
        [
            ("iface", "en0", "en0"),
            ("log_level", logging.INFO, logging.INFO),
            ("enforce_tls", "true", True),
            ("free_charging_service", "true", True),
            ("free_cert_install_service", "false", False),
            ("use_cpo_backend", "true", True),
            (
                "supported_protocols",
                "ISO_15118_20_AC, ISO_15118_2",
                [Protocol.ISO_15118_20_AC, Protocol.ISO_15118_2],
            ),
            ("supported_auth_options", "PNC", [AuthEnum.PNC]),
            ("supported_auth_options", "EIM,PNC", [AuthEnum.EIM, AuthEnum.PNC]),
            ("standby_allowed", "true", True),
            ("pki_path", "/other_path", "/other_path"),
            ("message_log_json", "false", False),
        ],
    )
    def test_update(self, config_name, new_value, expected_value):
        value = self.config.get_value(config_name)
        self.config.update({config_name: new_value})
        updated_value = self.config.get_value(config_name)
        assert value != updated_value
        if isinstance(updated_value, list):
            assert len(expected_value) == len(updated_value)
            for value in updated_value:
                assert value in expected_value
        else:
            assert expected_value == updated_value

    def test_pki_path_update(self):
        self.config.update({"pki_path": "./test_pki_path"})
        secc_leaf_new_path = CertPath.SECC_LEAF_PEM
        secc_leaf_path_expected = os.path.join(
            "./test_pki_path", "iso15118_2/certs/seccLeafCert.pem"
        )
        assert secc_leaf_new_path == secc_leaf_path_expected

    def test_update_key_is_not_in_config(self):
        with pytest.raises(ValueError):
            self.config.update({"key": "value"})
