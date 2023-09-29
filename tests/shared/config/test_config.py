import logging
from typing import List

import pytest

from iso15118.secc import Config
from iso15118.shared.messages.enums import AuthEnum, Protocol


class TestSECCConfig:
    @pytest.fixture(autouse=True)
    def config(self):
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
        ],
    )
    def test_update(self, config_name, new_value):
        value = self.config.as_dict()[config_name]
        self.config.update({config_name: new_value})
        updated_value = self.config.as_dict()[config_name]
        assert value != updated_value and new_value == updated_value
