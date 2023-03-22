import os

SHARED_CWD = os.path.dirname(os.path.abspath(__file__))
JAR_FILE_PATH = SHARED_CWD + "/EXICodec.jar"

WORK_DIR = os.getcwd()

ENV_PATH = WORK_DIR + "/libexec/everest/3rd_party/josev/.env"

PKI_Path = ""

def set_PKI_PATH(path: str) -> None:
    global PKI_Path
    PKI_Path = path

def get_PKI_PATH() -> str:
    return PKI_Path

MESSAGE_LOG_JSON = True
MESSAGE_LOG_EXI = False

V20_EVSE_SERVICES_CONFIG = SHARED_CWD + "/examples/15118_20_evse_service_config.json"

ENABLE_TLS_1_3 = False
shared_settings = None

ignoring_value_range = False

def set_ignoring_value_range(ignoring):
    global ignoring_value_range 
    ignoring_value_range = ignoring

def get_ignoring_value_range() -> bool:
    return ignoring_value_range
