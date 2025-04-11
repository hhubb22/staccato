try:
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, IPv6, TCP, UDP, ICMP
    from scapy.packet import Packet, Raw
except ImportError as e:
    raise ImportError(
        "Scapy is not installed. Please install it with: pip install scapy"
    ) from e

import base64
from typing import Dict, Any, Type
from core.exceptions import InvalidLayerTypeError, PacketCraftingError


class LayerCrafter:
    # 核心映射: API layer_type 字符串 -> Scapy 类
    SCAPY_LAYER_MAP: Dict[str, Type[Packet]] = {
        "Ether": Ether,
        "ARP": ARP,
        "IP": IP,
        "IPv6": IPv6,
        "TCP": TCP,
        "UDP": UDP,
        "ICMP": ICMP,
        # "DNS": DNS, # DNS 可能需要特殊处理嵌套
        "Raw": Raw,
        # --- 添加更多支持的协议 ---
    }

    def create_layer(self, layer_type: str, params: Dict[str, Any]) -> Packet:
        """
        Creates a Scapy layer object based on type and parameters.
        """
        scapy_class = self.SCAPY_LAYER_MAP.get(layer_type)
        if not scapy_class:
            raise InvalidLayerTypeError(
                f"Unsupported layer type: '{layer_type}'. Supported types: {list(self.SCAPY_LAYER_MAP.keys())}"
            )

        processed_params = params.copy()  # 避免修改原始字典

        # --- 特殊参数处理 ---
        if layer_type == "Raw" and "load" in processed_params:
            encoding = processed_params.pop("encoding", "text").lower()
            load_data = processed_params.get("load", "")
            try:
                if encoding == "base64":
                    processed_params["load"] = base64.b64decode(load_data)
                elif encoding == "hex":
                    processed_params["load"] = bytes.fromhex(load_data)
                elif encoding == "text":
                    processed_params["load"] = load_data.encode(
                        "utf-8"
                    )  # Or another appropriate encoding
                else:
                    raise ValueError(f"Unsupported encoding for Raw load: '{encoding}'")
            except Exception as e:
                raise PacketCraftingError(
                    f"Error decoding Raw load for encoding '{encoding}': {str(e)}"
                ) from e

        # (可选) 在这里添加对特定层参数的校验或转换逻辑
        # 例如: 校验 IP 地址格式, MAC 地址格式 (虽然 Pydantic 模型也可以做)

        # --- 实例化 Scapy 层 ---
        try:
            layer_obj = scapy_class(**processed_params)
            return layer_obj
        except TypeError as e:
            # Scapy 通常在参数不匹配时抛出 TypeError
            raise PacketCraftingError(
                f"Error instantiating layer '{layer_type}' with params {params}. Check parameters. Scapy error: {str(e)}"
            ) from e
        except Exception as e:
            # 捕获其他 Scapy 可能的异常
            raise PacketCraftingError(
                f"Unexpected error creating layer '{layer_type}': {str(e)}"
            ) from e
