from fastapi import APIRouter, HTTPException, Depends, status
from typing import Annotated  # For Python 3.9+ Dependency Injection syntax

# 假设 Service 和 Models 在可访问路径下
from services.packet_building_service import PacketBuildingService
from core.models import CraftFlexiblePacketRequest, SuccessResponse, ErrorResponse
from core.exceptions import (
    InvalidLayerTypeError,
    PacketCraftingError,
)  # 导入自定义异常

router = APIRouter()


# 依赖注入 Service 实例 (更高级的用法可以使用框架如 fastapi-injector)
# 简单示例: 直接实例化，或者使用 Depends 获取单例 (需要额外设置)
def get_packet_building_service():
    # 实际项目中可能从配置或工厂获取
    from crafting.layer_crafter import LayerCrafter  # 延迟导入或在服务中处理

    crafter = LayerCrafter()
    return PacketBuildingService(crafter=crafter)


PacketBuilderServiceDep = Annotated[
    PacketBuildingService, Depends(get_packet_building_service)
]


@router.post(
    "/build",
    response_model=SuccessResponse,
    summary="Build a packet layer by layer",
    description="Constructs a network packet based on a list of layer definitions.",
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid layer type or parameters",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Internal server error during crafting",
        },
    },
)
async def build_packet(
    request: CraftFlexiblePacketRequest, service: PacketBuilderServiceDep
):
    """
    Builds a packet based on the provided layer specifications.
    """
    try:
        # 调用 Service 层执行构建
        packet_info = await service.build_packet_from_layers(
            request
        )  # Service 方法可以是 async 或 sync
        return SuccessResponse(packet_info=packet_info)

    except InvalidLayerTypeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid layer type provided: {str(e)}",
        )
    except PacketCraftingError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,  # 或 500, 取决于错误性质
            detail=f"Error crafting packet: {str(e)}",
        )
    except Exception as e:
        # Log the unexpected error
        # logger.exception("Unexpected error during packet building")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}",
        )
