import sys
import os
import time
import asyncio
import subprocess
from loguru import logger

# 确保项目根目录在 path 中
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from src.utils.logger_config import setup_logging
from src.core.engine.manager import scanner_manager

# 全局保存前端进程对象，以便清理
frontend_process = None

def start_frontend():
    """启动前端开发服务器"""
    global frontend_process
    frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
    
    if not os.path.exists(frontend_dir):
        logger.warning("未找到 frontend 目录，跳过前端启动。")
        return

    logger.info("正在启动前端服务 (npm run dev)...")
    try:
        # Windows 下建议使用 shell=True 来正确解析 npm 命令
        # 或者显式使用 npm.cmd，但 shell=True 通用性较好
        frontend_process = subprocess.Popen(
            ["npm", "run", "dev"], 
            cwd=frontend_dir, 
            shell=True
        )
    except Exception as e:
        logger.error(f"启动前端服务失败: {e}")

def run_api():
    """启动 FastAPI 后端服务"""
    import uvicorn
    from src.api.main import app
    logger.info("正在启动 API 服务 (端口: 8000)...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

def main():
    # 初始化日志
    setup_logging()
    
    logger.info("=== WebAgent 综合扫描系统启动 ===")
    
    try:
        # 1. 启动前端 (非阻塞)
        start_frontend()
        
        # 2. 启动 API 服务 (阻塞主线程)
        run_api()
        
    except KeyboardInterrupt:
        logger.info("\n正在停止系统...")
    finally:
        # 确保所有子进程都已关闭
        scanner_manager.stop_all()
        
        if frontend_process:
            logger.info("正在关闭前端服务...")
            # Windows 下 shell=True 的进程 terminate 可能只杀死了 shell
            # 但作为开发脚本，这通常足够。如果需要更强力的杀进程，需要 psutil
            try:
                frontend_process.terminate()
            except:
                pass
                
        logger.info("系统已关闭。")

if __name__ == "__main__":
    main()
