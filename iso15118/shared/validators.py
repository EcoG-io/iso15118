"""
This module contains functions used by various pydantic validators throughout
the model classes for ISO 15118-2, ISO 15118-20, and SupportedAppProtocol
messages. Saves duplicated code.
"""

from typing import List


def validate_bytes_value_range(
    var_name: str, var_bytes: bytes, min_val: int, max_val: int
) -> bool:
    """
    Checks whether the provided integer value represented with the bytes object
    is within the allowed value range.

    var_name
        Name of the field being checked
    var_bytes
        The bytes object that holds the integer value
    min_val
        The lower bound (inclusive) of the allowed value range for the value
        represented by the given bytes object
    max_val
        The upper bound (inclusive) of the allowed value range for the value
        represented by the given bytes object
    """
    int_value = int.from_bytes(var_bytes, byteorder="big", signed=True)
    if not min_val <= int_value <= max_val:
        raise ValueError(
            f"The value {int_value} is outside the allowed value "
            f"range [{min_val}..{max_val}] for {var_name}"
        )
    return True


def one_field_must_be_set(
    field_options: List[str], values: dict, mutually_exclusive: bool = False
) -> bool:
    """
    In several messages, there is the option to choose one of two or more
    possible fields, where all fields are defined as optional in the
    corresponding model but at least one or exactly one of them needs to be set.
    For example, it could be either AC charging-related information or
    DC charging-related information.

    Args:
        field_options: List of optional field names and aliases of a model.
                       For each field, we need both the field name and the alias
                       because when instantiating a pydantic model, we use the
                       pythonic field names, but when de-serialising the model
                       through JSON via the EXI codec, we use the aliases.
        values: The dict with the model's fields
        mutually_exclusive: If true, then exactly one of the given field options
                            must be set. Otherwise, at least one of the given
                            field options must be set.
    """
    set_fields: List = []
    for field_name in field_options:
        field = values.get(f"{field_name}")
        # Important to not check for "if field" instead of "if field is not None" to
        # avoid situations in which field evaluates to 0 (which equals to False)
        if field is not None:
            set_fields.append(field)

    if mutually_exclusive and len(set_fields) != 1:
        raise ValueError(
            f"Exactly one field must be set but {len(set_fields)} "
            "are set instead. "
            f"\nSet fields: {set_fields}"
            f"\nField options: {field_options}"
        )

    if len(set_fields) == 0:
        raise ValueError(
            "At least one of these optional fields must be set "
            f"but {len(set_fields)} are set: {field_options}"
        )

    return True
