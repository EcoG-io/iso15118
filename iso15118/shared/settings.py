import os

import environs

SHARED_CWD = os.path.dirname(os.path.abspath(__file__))
JAR_FILE_PATH = SHARED_CWD + "/EXICodec.jar"

WORK_DIR = os.getcwd()

ENV_PATH = WORK_DIR + "/.env"

env = environs.Env(eager=False)
env.read_env(path=ENV_PATH)  # read .env file, if it exists

PKI_PATH = env.str("PKI_PATH", default=SHARED_CWD + "/pki/")
CERTS_GENERAL_PRIVATE_KEY_PASS_PATH = env.str(
    "CERTS_GENERAL_PRIVATE_KEY_PASS_PATH", default=None
)
MESSAGE_LOG_JSON = env.bool("MESSAGE_LOG_JSON", default=True)
MESSAGE_LOG_EXI = env.bool("MESSAGE_LOG_EXI", default=False)

V20_EVSE_SERVICES_CONFIG = env.str(
    "V20_SERVICE_CONFIG",
    default=SHARED_CWD + "/examples/15118_20_evse_service_config.json",
)
env.seal()  # raise all errors at once, if any
