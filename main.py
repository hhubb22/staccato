from fastapi import FastAPI
from contextlib import asynccontextmanager

# 导入 API 路由器
from api.v1 import api as api_v1  # 调整导入路径

# (可选) 导入配置加载
# from .core.config import settings

# (可选) 配置日志
# from .core.logging_config import setup_logging
# setup_logging()


# (可选) 应用启动和关闭事件 (例如: 初始化资源)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("Packet Builder API starting up...")
    # Load resources or setup connections here
    yield
    # Code to run on shutdown
    print("Packet Builder API shutting down...")
    # Clean up resources here


app = FastAPI(
    title="Packet Builder API",
    description="API for building network packets layer by layer using Scapy.",
    version="0.1.0",
    lifespan=lifespan,  # 使用 lifespan 管理启动/关闭事件
)

# 挂载 v1 版本的 API 路由
app.include_router(api_v1.router, prefix="/api/v1")


# (可选) 添加根路径或其他基本端点
@app.get("/", tags=["Default"])
async def read_root():
    return {"message": "Welcome to the Packet Builder API!"}


# (可选) 添加中间件 (例如 CORS)
# from fastapi.middleware.cors import CORSMiddleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"], # 允许所有来源 (生产环境应更严格)
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
