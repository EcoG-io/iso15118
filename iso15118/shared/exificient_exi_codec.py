import json
import logging
from builtins import Exception

from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.settings import JAR_FILE_PATH

logger = logging.getLogger(__name__)


def compare_messages(json_to_encode, decoded_json):
    json_obj = json.loads(json_to_encode)
    decoded_json_obj = json.loads(decoded_json)
    return sorted(json_obj.items()) == sorted(decoded_json_obj.items())


class ExificientEXICodec(IEXICodec):
    def __init__(self):
        from py4j.java_gateway import JavaGateway

        logging.getLogger("py4j").setLevel(logging.CRITICAL)
        self.gateway = JavaGateway.launch_gateway(
            classpath=JAR_FILE_PATH,
            die_on_exit=True,
            javaopts=["--add-opens", "java.base/java.lang=ALL-UNNAMED"],
        )

        self.exi_codec = self.gateway.jvm.com.siemens.ct.exi.main.cmd.EXICodec()

    def encode(self, message: str, namespace: str) -> bytes:
        """
        Calls the Exificient EXI implmentation to encode input json.
        Returns a byte[] for the input message if conversion was successful.
        """
        exi = self.exi_codec.encode(message, namespace)

        if exi is None:
            raise Exception(self.exi_codec.get_last_encoding_error())
        return exi

    def decode(self, stream: bytes, namespace: str) -> str:
        """
        Calls the EXIficient EXI implementation to decode the input EXI stream.
        Returns a JSON representation of the input EXI stream if the conversion
        was successful.
        """
        decoded_message = self.exi_codec.decode(stream, namespace)

        if decoded_message is None:
            raise Exception(self.exi_codec.get_last_decoding_error())
        return decoded_message

    def get_version(self) -> str:
        """
        Returns the version of the Exificient codec
        """
        return self.exi_codec.get_version()
