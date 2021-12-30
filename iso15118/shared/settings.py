import os

import environs

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
JAR_FILE_PATH = ROOT_DIR + "/EXICodec.jar"

WORK_DIR = os.getcwd()
SHARED_CWD = WORK_DIR + "/iso15118/shared/"

ENV_PATH = WORK_DIR + "/.env"

env = environs.Env(eager=False)
env.read_env(path=ENV_PATH)  # read .env file, if it exists

PKI_PATH = env.str("PKI_PATH", default=SHARED_CWD + "pki/")
MESSAGE_LOG_JSON = env.bool("MESSAGE_LOG_JSON", default=True)
MESSAGE_LOG_EXI = env.bool("MESSAGE_LOG_EXI", default=False)

env.seal()  # raise all errors at once, if any
