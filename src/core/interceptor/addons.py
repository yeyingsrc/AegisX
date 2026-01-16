import os
import sys

# 确保 src 可被导入
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from mitmproxy import http
from src.core.interceptor.handler import InterceptorHandler
from loguru import logger

def setup_logging():
    """配置拦截器日志"""
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../logs"))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    logger.add(
        os.path.join(log_dir, "interceptor.log"),
        rotation="10 MB",
        retention="1 week",
        level="INFO",
        encoding="utf-8",
        enqueue=True
    )
    logger.add(
        os.path.join(log_dir, "error.log"),
        rotation="10 MB",
        retention="1 week",
        level="ERROR",
        encoding="utf-8",
        backtrace=True,
        diagnose=True,
        enqueue=True
    )

class InterceptorAddon:
    """Mitmproxy Addon 脚本入口"""
    
    def __init__(self):
        setup_logging()
        self.handler = InterceptorHandler()
        logger.info("Mitmproxy 拦截器插件已加载")

    def response(self, flow: http.HTTPFlow):
        """处理响应事件 (此时请求和响应都已就绪)"""
        try:
            self.handler.process_flow(flow)
        except Exception as e:
            logger.error(f"处理流量时出错: {str(e)}")

# Mitmproxy 加载该脚本时会寻找 addons 变量
addons = [
    InterceptorAddon()
]
