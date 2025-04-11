from fastapi import APIRouter

# 导入各个端点的路由器
from api.v1.endpoints import packet_builder  # 调整导入路径

router = APIRouter()

# 包含 packet_builder 路由
router.include_router(
    packet_builder.router, prefix="/packets", tags=["Packet Building"]
)

# (未来可以包含其他端点的路由)
# from .endpoints import interfaces
# router.include_router(interfaces.router, prefix="/network", tags=["Network Info"])
