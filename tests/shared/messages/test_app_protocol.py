import json

from iso15118.shared.exi_codec import CustomJSONDecoder
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)


# Test json strings recorded 28.7.2022 with Comemso Multi Mobile DC protocol tester
class TestAppProtocol_MessageCreation:
    def test_common_SupportedAppProtocolRes_messages_can_be_parsed(self):
        decoded_dict = json.loads(
            '{"supportedAppProtocolRes": {"ResponseCode": "OK_SuccessfulNegotiation",'
            '"SchemaID": 0}}',
            cls=CustomJSONDecoder,
        )

        message = SupportedAppProtocolRes.parse_obj(
            decoded_dict["supportedAppProtocolRes"]
        )
        assert isinstance(message, SupportedAppProtocolRes)

    def test_common_SupportedAppProtocolReq_messages_can_be_parsed(self):
        decoded_dict = json.loads(
            '{"supportedAppProtocolReq":{"AppProtocol":[{"ProtocolNamespace":'
            '"urn:iso:15118:2:2013:MsgDef","VersionNumberMajor":2,'
            '"VersionNumberMinor":0,"SchemaID":0,"Priority":1}]}}',
            cls=CustomJSONDecoder,
        )

        message = SupportedAppProtocolReq.parse_obj(
            decoded_dict["supportedAppProtocolReq"]
        )
        assert isinstance(message, SupportedAppProtocolReq)
