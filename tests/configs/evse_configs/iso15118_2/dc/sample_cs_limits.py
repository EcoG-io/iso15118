def get_cs_limits_dc():
    cs_limits = """ {
      "evses": [
        {
          "evse_id": "DE*SWT*E123456789",
          "ac": {
            "max_current": {
              "l1": 16,
              "l2": 16,
              "l3": 16
            },
            "nominal_voltage": 230,
            "rcd_error": false
          }
        }
      ]
    }
    """
    return cs_limits
