from scapy.packet import Packet
from typing import Optional


def get_packet_representation(
    packet: Packet, output_format: Optional[str] = None
) -> str:
    """
    Returns a string representation of the packet based on requested format.
    Defaults to showing the packet summary if no specific format requested.
    """
    if output_format == "hex":
        return packet.hexdump()
    elif output_format == "raw":
        return str(packet)
    else:
        return packet.summary()
