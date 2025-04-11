# src/packet_builder/core/exceptions.py

"""
Custom exception classes for the Packet Builder application.

This module defines a base exception and specific exceptions for different
error conditions that can occur within the application logic, allowing for
more granular error handling in higher layers (like the API).
"""


class PacketBuilderBaseError(Exception):
    """Base class for all custom exceptions in this application."""

    def __init__(
        self,
        message: str = "An unspecified error occurred in the Packet Builder application.",
    ):
        self.message = message
        super().__init__(self.message)


class ConfigurationError(PacketBuilderBaseError):
    """Exception raised for errors related to application configuration."""

    def __init__(self, message: str = "Application configuration error."):
        super().__init__(message)


class InvalidLayerTypeError(PacketBuilderBaseError):
    """
    Exception raised when an unsupported or unknown layer_type is requested
    during packet building.
    """

    def __init__(self, layer_type: str, supported_types: list[str] | None = None):
        message = f"Invalid or unsupported layer type specified: '{layer_type}'."
        if supported_types:
            message += f" Supported types are: {', '.join(supported_types)}"
        super().__init__(message)
        self.layer_type = layer_type
        self.supported_types = supported_types


class PacketCraftingError(PacketBuilderBaseError):
    """
    Exception raised during the Scapy packet crafting process, such as
    invalid parameters for a layer, errors during layer instantiation,
    or issues combining layers.
    """

    def __init__(self, message: str = "An error occurred during packet crafting."):
        super().__init__(message)


class PayloadEncodingError(PacketCraftingError):
    """
    Specific exception for errors encountered while encoding or decoding
    payload data (e.g., for the Raw layer).
    Inherits from PacketCraftingError.
    """

    def __init__(self, encoding: str, original_error: Exception | None = None):
        message = f"Error processing payload with encoding '{encoding}'."
        if original_error:
            message += f" Original error: {str(original_error)}"
        super().__init__(message)
        self.encoding = encoding
        self.original_error = original_error


class SendPermissionError(PacketBuilderBaseError):
    """
    Exception raised when attempting to send a packet without sufficient
    permissions (e.g., root/administrator privileges).
    Note: This relates to the sending part, potentially separate from building.
    """

    def __init__(
        self,
        message: str = "Insufficient permissions to send packet. Root/Administrator privileges may be required.",
    ):
        super().__init__(message)


# Example of how to raise an exception:
# raise InvalidLayerTypeError("MyCustomLayer", supported_types=["Ether", "IP"])

# Example of how to catch a specific exception:
# try:
#     # ... crafting logic ...
# except InvalidLayerTypeError as e:
#     # Handle specific error
#     print(e)
# except PacketCraftingError as e:
#     # Handle general crafting error
#     print(e)
# except PacketBuilderBaseError as e:
#     # Handle any custom app error
#     print(f"Application error: {e}")
