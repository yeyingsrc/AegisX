import os
import sys

# 将 src 添加到 Python 路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from src.config.settings import settings

def test_config_loading():
    print("--- 正在测试配置加载 ---")
    print(f"Manager 模型: {settings.MODEL_NAME_MANAGER}")
    print(f"白名单列表: {settings.TARGET_WHITELIST}")
    print(f"Redis 地址: {settings.REDIS_URL}")
    print(f"日志级别: {settings.LOG_LEVEL}")
    
    # 模拟从环境变量读取
    os.environ["TARGET_WHITELIST"] = '["test.com", "192.168.1.1"]'
    # 重新加载（在实际应用中，settings 实例通常只初始化一次，这里仅为演示）
    from importlib import reload
    import src.config.settings
    reload(src.config.settings)
    
    print("\n--- 环境变量覆盖后 ---")
    print(f"新白名单列表: {src.config.settings.settings.TARGET_WHITELIST}")

if __name__ == "__main__":
    test_config_loading()
