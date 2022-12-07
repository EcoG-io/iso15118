import json
from dataclasses import dataclass

import pytest

from iso15118.shared.exi_codec import CustomJSONDecoder
from iso15118.shared.messages.datatypes import (
    PVRemainingTimeToBulkSOC,
    PVRemainingTimeToFullSOC,
)
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from tests.shared.messages.exi_message_container import ExiMessageContainer


# Test strings recorded 28.7.2022 with Comemso Multi Mobile DC Protocol Tester
ISO_TEST_MESSAGES = [
    ExiMessageContainer(
        message_name="SessionSetupReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"0000000000000000"},"Body":'
        '{"SessionSetupReq":{"EVCCID":"020000000001"}}}}',
    ),
    ExiMessageContainer(
        message_name="SessionSetupRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body":{"SessionSetupRes":{"ResponseCode":'
        '"OK_NewSessionEstablished","EVSEID": "CH123DW123",'
        '"EVSETimeStamp": 1659025194}}}}',
    ),
    ExiMessageContainer(
        message_name="ServiceDiscoveryReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"ServiceDiscoveryReq":{"ServiceScope":"www.vector.com","ServiceCategory":'
        '"EVCharging"}}}}',
    ),
    ExiMessageContainer(
        message_name="ServiceDiscoveryRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},"Body":'
        '{"ServiceDiscoveryRes": {"ResponseCode": "OK", "PaymentOptionList":'
        '{"PaymentOption": ["ExternalPayment"]}, "ChargeService":'
        '{"ServiceID": 1, "ServiceName": "AC_DC_Charging", "ServiceCategory":'
        '"EVCharging", "FreeService": true, "SupportedEnergyTransferMode":'
        '{"EnergyTransferMode": ["DC_extended"]}}}}}}',
    ),
    ExiMessageContainer(
        message_name="PaymentServiceSelectionReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"PaymentServiceSelectionReq":{"SelectedPaymentOption":'
        '"ExternalPayment","SelectedServiceList":{"SelectedService":'
        '[{"ServiceID":1}]}}}}}',
    ),
    ExiMessageContainer(
        message_name="PaymentServiceSelectionRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body": {"PaymentServiceSelectionRes": {"ResponseCode": "OK"}}}}',
    ),
    ExiMessageContainer(
        message_name="AuthorizationReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"AuthorizationReq":{}}}}',
    ),
    ExiMessageContainer(
        message_name="AuthorizationRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},"Body":'
        '{"AuthorizationRes": {"ResponseCode": "OK", "EVSEProcessing":'
        '"Finished"}}}}',
    ),
    ExiMessageContainer(
        message_name="ChargeParameterDiscoveryReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"ChargeParameterDiscoveryReq":{"MaxEntriesSAScheduleTuple":16,'
        '"RequestedEnergyTransferMode":"DC_extended","DC_EVChargeParameter":'
        '{"DepartureTime":0,"DC_EVStatus":{"EVReady":false,"EVErrorCode":'
        '"NO_ERROR","EVRESSSOC":20},"EVMaximumCurrentLimit":{"Multiplier":'
        '1,"Unit":"A","Value":8},"EVMaximumPowerLimit":{"Multiplier":3,'
        '"Unit":"W","Value":29},"EVMaximumVoltageLimit":{"Multiplier":2,'
        '"Unit":"V","Value":5},"EVEnergyCapacity":{"Multiplier":3,"Unit":'
        '"Wh","Value":200},"EVEnergyRequest":{"Multiplier":3,"Unit":"Wh",'
        '"Value":160},"FullSOC":99,"BulkSOC":80}}}}}',
    ),
    ExiMessageContainer(
        message_name="ChargeParameterDiscoveryRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body": {"ChargeParameterDiscoveryRes": {"ResponseCode": "OK",'
        '"EVSEProcessing": "Finished", "SAScheduleList": {"SAScheduleTuple":'
        '[{"SAScheduleTupleID": 1, "PMaxSchedule": {"PMaxScheduleEntry":'
        '[{"PMax": {"Value": 420, "Multiplier": 2, "Unit": "W"},'
        '"RelativeTimeInterval": {"start": 0, "duration": 13714}}]}}]},'
        '"DC_EVSEChargeParameter": {"DC_EVSEStatus": {"NotificationMaxDelay":'
        '0, "EVSENotification": "None", "EVSEIsolationStatus": "Invalid",'
        '"EVSEStatusCode": "EVSE_Ready"}, "EVSEMaximumCurrentLimit":'
        '{"Value": 25, "Multiplier": 0, "Unit":"A"},"EVSEMaximumPowerLimit":'
        '{"Value": 4200, "Multiplier": 1, "Unit": "W"},'
        '"EVSEMaximumVoltageLimit": {"Value": 1000, "Multiplier": 0, "Unit":'
        '"V"}, "EVSEMinimumCurrentLimit": {"Value": 4, "Multiplier": 0,'
        '"Unit": "A"}, "EVSEMinimumVoltageLimit": {"Value":250,"Multiplier":'
        '0, "Unit": "V"}, "EVSECurrentRegulationTolerance": {"Value": 0,'
        '"Multiplier": 0, "Unit": "A"}, "EVSEPeakCurrentRipple": {"Value":'
        '1, "Multiplier": 0, "Unit": "A"}, "EVSEEnergyToBeDelivered":'
        '{"Value": 10000, "Multiplier": 0, "Unit": "Wh"}}}}}}',
    ),
    ExiMessageContainer(
        message_name="CableCheckReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"CableCheckReq":{"DC_EVStatus":{"EVReady":true,"EVErrorCode":'
        '"NO_ERROR","EVRESSSOC":20}}}}}',
    ),
    ExiMessageContainer(
        message_name="CableCheckRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body": {"CableCheckRes": {"ResponseCode": "OK", "DC_EVSEStatus":'
        '{"NotificationMaxDelay": 0, "EVSENotification": "None",'
        '"EVSEIsolationStatus": "Invalid", "EVSEStatusCode": "EVSE_Ready"},'
        '"EVSEProcessing": "Ongoing"}}}}',
    ),
    ExiMessageContainer(
        message_name="PreChargeReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"PreChargeReq":{"DC_EVStatus":{"EVReady":true,"EVErrorCode":'
        '"NO_ERROR","EVRESSSOC":20},"EVTargetVoltage":{"Multiplier":2,'
        '"Unit":"V","Value":4},"EVTargetCurrent":{"Multiplier":0,"Unit":'
        '"A","Value":0}}}}}',
    ),
    ExiMessageContainer(
        message_name="PreChargeRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body": {"PreChargeRes": {"ResponseCode": "OK", "DC_EVSEStatus":'
        '{"NotificationMaxDelay": 0, "EVSENotification": "None",'
        '"EVSEIsolationStatus": "Valid", "EVSEStatusCode": "EVSE_Ready"},'
        '"EVSEPresentVoltage": {"Value": 0, "Multiplier": 0,"Unit":"V"}}}}}',
    ),
    ExiMessageContainer(
        message_name="PowerDeliveryReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"PowerDeliveryReq":{"ChargeProgress":"Start","SAScheduleTupleID":1,'
        '"DC_EVPowerDeliveryParameter":{"DC_EVStatus":{"EVReady":true,'
        '"EVErrorCode":"NO_ERROR","EVRESSSOC":20},"BulkChargingComplete":'
        'false,"ChargingComplete":false}}}}}',
    ),
    ExiMessageContainer(
        message_name="PowerDeliveryRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "82DBA3A44ED6E5B9"},'
        '"Body": {"PowerDeliveryRes": {"ResponseCode": "OK", "DC_EVSEStatus":'
        '{"NotificationMaxDelay": 0, "EVSENotification": "None",'
        '"EVSEIsolationStatus": "Valid", "EVSEStatusCode": "EVSE_Ready"}}}}}',
    ),
    ExiMessageContainer(
        message_name="CurrentDemandReq",
        json_str='{"V2G_Message":{"Header":{"SessionID":"82DBA3A44ED6E5B9"},"Body":'
        '{"CurrentDemandReq":{"DC_EVStatus":{"EVReady":true,"EVErrorCode":'
        '"NO_ERROR","EVRESSSOC":20},"EVTargetCurrent":{"Multiplier":0,"Unit":'
        '"A","Value":0},"EVMaximumVoltageLimit":{"Multiplier":2,"Unit":"V",'
        '"Value":5},"EVMaximumCurrentLimit":{"Multiplier":1,"Unit":"A",'
        '"Value":8},"EVMaximumPowerLimit":{"Multiplier":3,"Unit":"W","Value":'
        '29},"BulkChargingComplete":false,"ChargingComplete":false,'
        '"RemainingTimeToFullSoC":{"Multiplier":3,"Unit":"s","Value":'
        '32767},"RemainingTimeToBulkSoC":{"Multiplier":3,"Unit":"s",'
        '"Value":32767},"EVTargetVoltage":{"Multiplier":1,"Unit":"V",'
        '"Value":45}}}}}',
    ),
    ExiMessageContainer(
        message_name="CurrentDemandRes",
        json_str='{"V2G_Message": {"Header": {"SessionID": "4FEE7D86002F8A31"},'
        '"Body": {"CurrentDemandRes": {"ResponseCode": "OK", "DC_EVSEStatus":'
        '{"NotificationMaxDelay": 0, "EVSENotification": "None",'
        '"EVSEIsolationStatus": "Valid", "EVSEStatusCode": "EVSE_Ready"},'
        '"EVSEPresentVoltage": {"Value": 400, "Multiplier": 0, "Unit": "V"},'
        '"EVSEPresentCurrent": {"Value": 15, "Multiplier": 0, "Unit": "A"},'
        '"EVSECurrentLimitAchieved": false, "EVSEVoltageLimitAchieved":'
        'false, "EVSEPowerLimitAchieved": false, "EVSEMaximumVoltageLimit":'
        '{"Value": 1000, "Multiplier": 0, "Unit": "V"},'
        '"EVSEMaximumCurrentLimit": {"Value": 25, "Multiplier": 0, "Unit":'
        '"A"}, "EVSEMaximumPowerLimit": {"Value": 4200, "Multiplier": 1,'
        '"Unit": "W"}, "EVSEID": "CH123DW123", "SAScheduleTupleID": 1,'
        '"ReceiptRequired": false}}}}',
    ),
    ExiMessageContainer(
        description="Audi E-Tron GT recorded at 2022-12-15",
        message_name="CurrentDemandReq",
        json_str='{"V2G_Message": {"Header": {"SessionID": "AC1DECE39DBE831A"},'
        '"Body": {"CurrentDemandReq": {"DC_EVStatus":{"EVReady":'
        'true,"EVErrorCode":"NO_ERROR","EVRESSSOC":76},"EVTargetCurrent":'
        '{"Multiplier":-1,"Unit":"A","Value":0},"EVMaximumVoltageLimit":'
        '{"Multiplier":-1,"Unit":"V","Value":8490},"EVMaximumCurrentLimit":'
        '{"Multiplier":-1,"Unit":"A","Value":4000},"BulkChargingComplete":'
        'false,"ChargingComplete":false,"RemainingTimeToFullSoC":'
        '{"Multiplier":0,"Unit":"s","Value":10680},"EVTargetVoltage":'
        '{"Multiplier":-1,"Unit":"V","Value":8390}}}}}',
    ),
]


class TestIso15118_V2_MessageCreation:
    # Test data recorded 28.7.2022 with Comemso Multi Mobile DC Protocol Tester
    # are showing exactly how CCS Protocol is implemented in real world.
    # The Numbers for SOC are exceeding the limits defined in standard.
    PVRemainingTimeToFullSOC._max_limit = 32767000
    PVRemainingTimeToBulkSOC._max_limit = 32767000

    @pytest.mark.parametrize(
        "message",
        ISO_TEST_MESSAGES,
        ids=[f"parse_and_create_{msg.message_name}" for msg in ISO_TEST_MESSAGES],
    )
    def test_common_v2g_messages_can_be_parsed_and_created(self, message: ExiMessageContainer):
        decoded_dict = json.loads(message.json_str, cls=CustomJSONDecoder)

        message = V2GMessageV2.parse_obj(decoded_dict["V2G_Message"])
        assert isinstance(message, V2GMessageV2)
