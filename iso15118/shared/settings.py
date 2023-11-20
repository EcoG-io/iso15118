import os
from typing import Optional

import environs


class SettingKey:
    PKI_PATH = "PKI_PATH"
    MESSAGE_LOG_JSON = "MESSAGE_LOG_JSON"
    MESSAGE_LOG_EXI = "MESSAGE_LOG_EXI"
    V20_SERVICE_CONFIG = "V20_SERVICE_CONFIG"
    ENABLE_TLS_1_3 = "ENABLE_TLS_1_3"


shared_settings = {}
SHARED_CWD = os.path.dirname(os.path.abspath(__file__))
JAR_FILE_PATH = SHARED_CWD + "/EXICodec.jar"

WORK_DIR = os.getcwd()


def load_shared_settings(env_path: Optional[str] = None):
    env = environs.Env(eager=False)
    env.read_env(path=env_path)  # read .env file, if it exists

    settings = {
        SettingKey.PKI_PATH: env.str("PKI_PATH", default=SHARED_CWD + "/pki/"),
        SettingKey.MESSAGE_LOG_JSON: env.bool("MESSAGE_LOG_JSON", default=True),
        SettingKey.MESSAGE_LOG_EXI: env.bool("MESSAGE_LOG_EXI", default=False),
        SettingKey.V20_SERVICE_CONFIG: env.str(
            "V20_SERVICE_CONFIG",
            default=SHARED_CWD + "/examples/secc/15118_20/service_config.json",
        ),
        SettingKey.ENABLE_TLS_1_3: env.bool("ENABLE_TLS_1_3", default=False),
    }
    shared_settings.update(settings)
    env.seal()  # raise all errors at once, if any
