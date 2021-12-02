import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER_CONF_PATH = os.path.join(ROOT_DIR, 'logging.conf')
PKI_PATH = os.path.join(ROOT_DIR, 'pki/')

# Log the messages that are EXI encoded and decoded as JSON for debugging
# purposes. Must be True or False
MESSAGE_LOG_JSON = True
MESSAGE_LOG_EXI = False
