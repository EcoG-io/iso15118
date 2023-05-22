from .context import Context

context = Context()

INT_16_MAX = 2**15 - 1

def float2Value_Multiplier(value:float):
    p_value: int = 0
    p_multiplier: int = 0
    exponent: int = 0

    # Check if it is an integer or a decimal number
    if (value - int(value)) != 0:
        exponent = 2

    for x in range(exponent, -4, -1):
        if (value * pow(10, x)) < INT_16_MAX:
            exponent = x
            break

    p_multiplier = int(-exponent)
    p_value = int(value * pow(10, exponent))

    return p_value, p_multiplier

def PhysicalValueType2float(p_value:int, p_multiplier:int) -> float:
    value:float = p_value * pow(10, p_multiplier)
    return value
