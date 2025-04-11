from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Literal, Union


# --- 基础模型 ---
class PacketRepresentation(BaseModel):
    format: str
    value: str


class PacketInfo(BaseModel):
    type_requested: Optional[str] = (
        None  # 在灵活模式下可能不太适用，或者可以设为 "flexible_build"
    )
    summary: str
    representation: PacketRepresentation
    length_bytes: Optional[int] = None


class SuccessResponse(BaseModel):
    status: str = Field("success", examples=["success"])
    packet_info: PacketInfo


class ErrorResponse(BaseModel):
    detail: str


# --- 灵活构建模型 ---
class LayerDefinition(BaseModel):
    layer_type: str = Field(
        ...,
        description="Protocol name (e.g., 'Ether', 'IP', 'TCP', 'UDP', 'Raw')",
        examples=["Ether", "IP", "UDP", "Raw"],
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for this layer, matching Scapy fields",
    )


class CraftFlexiblePacketRequest(BaseModel):
    # mode: Literal["flexible"] # 如果只支持此模式，mode 字段可以省略
    layers: List[LayerDefinition] = Field(
        ..., min_length=1, description="List of layers from outer to inner"
    )
    output_format: Literal["base64", "hex", "summary"] = Field(
        "base64", description="Output format for the packet representation"
    )

    # Pydantic v1 validator syntax, adjust for v2 if needed
    # @validator('output_format')
    # def validate_output_format(cls, v):
    #     if v not in ["base64", "hex", "summary"]:
    #         raise ValueError("Invalid output format. Choose 'base64', 'hex', or 'summary'")
    #     return v
