import os

import environs

SHARED_CWD = os.path.dirname(os.path.abspath(__file__))
JAR_FILE_PATH = SHARED_CWD + "/EXICodec.jar"

WORK_DIR = os.getcwd()

ENV_PATH = WORK_DIR + "/.env"

env = environs.Env(eager=False)
env.read_env(path=ENV_PATH)  # read .env file, if it exists

shared_settings = {
    "pki_path": env.str("PKI_PATH", default=SHARED_CWD + "/pki/"),
    "message_log_json": env.bool("MESSAGE_LOG_JSON", default=True),
    "message_log_exi": env.bool("MESSAGE_LOG_EXI", default=False),
    "v20_evse_services_config": env.str(
        "V20_SERVICE_CONFIG",
        default=SHARED_CWD + "/examples/secc/15118_20/service_config.json",
    ),
    "enable_tls_1_3": env.bool("ENABLE_TLS_1_3", default=False),
}
env.seal()  # raise all errors at once, if any
