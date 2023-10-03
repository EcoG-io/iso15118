import logging
import os

import pytest

from iso15118.secc import Config
from iso15118.shared.messages.enums import AuthEnum, Protocol
from iso15118.shared.security import CertPath
from iso15118.shared.settings import SettingKey, shared_settings


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
            supported_protocols=[Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121],
            supported_auth_options=[AuthEnum.EIM],
            standby_allowed=False,
        )

    @pytest.mark.parametrize(
        "config_name, new_value",
        [
            ("iface", "en0"),
            ("log_level", logging.INFO),
            ("enforce_tls", True),
            ("free_charging_service", True),
            ("free_cert_install_service", False),
            ("use_cpo_backend", True),
            (
                "supported_protocols",
                [Protocol.ISO_15118_20_AC, Protocol.ISO_15118_20_WPT],
            ),
            ("supported_auth_options", [AuthEnum.PNC]),
            ("standby_allowed", True),
            ("pki_path", "/other_path"),
            ("message_log_json", False),
        ],
    )
    def test_update(self, config_name, new_value):
        value = self.config.get_value(config_name)
        self.config.update({config_name: new_value})
        updated_value = self.config.get_value(config_name)
        assert value != updated_value and new_value == updated_value

    @pytest.mark.parametrize(
        "config",
        [
            {"iface": "en0", "log_level": logging.INFO, "enforce_tls": True},
            {"pki_path": "/other_path", "message_log_json": False},
            {"iface": "en0", "message_log_json": False},
        ],
    )
    def test_update_multiple(self, config):
        first_values = {}
        for key, value in config.items():
            first_values[key] = self.config.get_value(key)
        self.config.update(config)
        for key, value in config.items():
            assert first_values[key] != self.config.get_value(
                key
            ) and value == self.config.get_value(key)

    def test_pki_path_update(self):
        self.config.update({"pki_path": "./test_pki_path"})
        secc_leaf_new_path = CertPath.SECC_LEAF_PEM
        secc_leaf_path_expected = os.path.join(
            "./test_pki_path", "iso15118_2/certs/seccLeafCert.pem"
        )
        assert secc_leaf_new_path == secc_leaf_path_expected

    def test_update_with_wrong_value_type(self):
        with pytest.raises(TypeError):
            self.config.update({"pki_path": None, "message_log_json": "False"})

    def test_update_key_is_not_in_config(self):
        with pytest.raises(ValueError):
            self.config.update({"key": "value"})
