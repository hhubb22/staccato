from scapy.packet import Packet  # 导入 Scapy Packet 类型
from typing import Dict  # For type hinting

from core.models import CraftFlexiblePacketRequest, PacketInfo
from crafting.layer_crafter import LayerCrafter
from core.packet_utils import get_packet_representation
from core.exceptions import PacketCraftingError


class PacketBuildingService:
    def __init__(self, crafter: LayerCrafter):
        self.crafter = crafter

    # 可以是 async def 如果内部有 await 操作 (例如异步 I/O 或调用异步 crafter)
    async def build_packet_from_layers(
        self, request_data: CraftFlexiblePacketRequest
    ) -> PacketInfo:
        """
        Builds a Scapy packet from a list of layer definitions.
        """
        packet: Packet | None = None
        current_summary = ""

        for layer_def in request_data.layers:
            try:
                current_layer_obj = self.crafter.create_layer(
                    layer_type=layer_def.layer_type, params=layer_def.params
                )
                # 使用 / 操作符叠加层
                packet = packet / current_layer_obj if packet else current_layer_obj
                current_summary = packet.summary()  # 获取当前摘要
            except Exception as e:
                # 包装 Scapy 在叠加时可能产生的错误
                raise PacketCraftingError(
                    f"Error combining layer '{layer_def.layer_type}' "
                    f"onto packet '{current_summary}': {str(e)}"
                ) from e

        if packet is None:
            raise PacketCraftingError("No layers were successfully processed.")

        # 构建成功, 获取表示形式
        representation = get_packet_representation(packet, request_data.output_format)

        packet_info = PacketInfo(
            summary=packet.summary(),
            representation=representation,
            length_bytes=len(packet),  # 获取报文长度
        )
        return packet_info
