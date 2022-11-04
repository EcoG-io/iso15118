def get_cs_config_dc():
    dc_config = """{
    "sw_version": "v1.0.1",
    "hw_version": "v2.0.0",
    "number_of_evses": 1,
    "parameters": [
      {
        "evse_id": "DE*SWT*E123456789",
        "connectors": [
          {
            "id": 1,
            "services": {
              "ac": {
                "connector_type": "AC_three_phase_core",
                "nominal_voltage": 230,
                "free_service": true,
                "control_mode": "",
                "mobility_needs": "",
                "pricing": ""
              }
            }
          }
        ],
        "supports_eim": true,
        "network_interface": "en0"
      }
    ]
  }"""
    return dc_config
