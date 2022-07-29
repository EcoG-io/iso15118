import json
from dataclasses import dataclass

from iso15118.shared.exceptions import V2GMessageValidationError
from iso15118.shared.messages.iso15118_2.body import Body, ChargeParameterDiscoveryReq
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage


@dataclass
class InvalidV2GMessage:
    msg: str
    msg_body: Body
    response_code: ResponseCode


invalid_v2g_2_messages = [
    (
        InvalidV2GMessage(
            (
                # [V2G2-477]
                # Parameters are not compatible with RequestedEnergyTransferMode
                '{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
                '{"ChargeParameterDiscoveryReq":{"MaxEntriesSAScheduleTuple":16,'
                '"RequestedEnergyTransferMode":"AC_three_phase_core",'
                '"DC_EVChargeParameter":'
                '{"DepartureTime":0,"DC_EVStatus":{"EVReady":false,"EVErrorCode":'
                '"NO_ERROR","EVRESSSOC":20},"EVMaximumCurrentLimit":{"Multiplier":'
                '1,"Unit":"A","Value":8},"EVMaximumPowerLimit":{"Multiplier":3,'
                '"Unit":"W","Value":29},"EVMaximumVoltageLimit":{"Multiplier":2,'
                '"Unit":"V","Value":5},"EVEnergyCapacity":{"Multiplier":3,"Unit":'
                '"Wh","Value":200},"EVEnergyRequest":{"Multiplier":3,"Unit":"Wh",'
                '"Value":160},"FullSOC":99,"BulkSOC":80}}}}}'
            ),
            ChargeParameterDiscoveryReq,
            ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
        )
    ),
]


def test_invalid_v2g_2_messages():
    for message in invalid_v2g_2_messages:
        try:
            invalid_msg = json.loads(message.msg)
            V2GMessage.parse_obj(invalid_msg["V2G_Message"])
        except V2GMessageValidationError as exc:
            assert exc.message is message.msg_body
            assert exc.response_code is message.response_code
