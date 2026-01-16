import json
import redis
import sys
import os

# 将项目根目录添加到 sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.utils.redis_helper import redis_helper
from src.config.settings import settings

def test_history_params_storage():
    print("Starting Redis History Params Test...")
    
    # 清理旧数据 (为了测试准确性)
    host = "test-history.com"
    redis_key = f"webagent:host:{host}:params"
    redis_helper.client.delete(redis_key)
    
    # 场景 1: GET 请求带 Query 参数
    task1 = {
        "url": f"http://{host}/api/v1/users?user_id=1001&type=admin",
        "method": "GET",
        "headers": {"Host": host}
    }
    redis_helper.push_task(task1)
    print("Pushed Task 1 (GET Query)")

    # 场景 2: POST 请求带 JSON Body
    task2 = {
        "url": f"http://{host}/api/v1/login",
        "method": "POST",
        "headers": {"Host": host, "Content-Type": "application/json"},
        "body": json.dumps({"username": "admin", "password": "123", "token": "abc"})
    }
    redis_helper.push_task(task2)
    print("Pushed Task 2 (POST JSON)")

    # 场景 3: POST 请求带 Form Body
    task3 = {
        "url": f"http://{host}/submit",
        "method": "POST",
        "headers": {"Host": host, "Content-Type": "application/x-www-form-urlencoded"},
        "body": "search=query&filter=active"
    }
    redis_helper.push_task(task3)
    print("Pushed Task 3 (POST Form)")
    
    # 场景 4: 无 Host Header，从 URL 提取
    task4 = {
        "url": f"http://{host}/other?extra=param",
        "method": "GET",
        # no headers
    }
    redis_helper.push_task(task4)
    print("Pushed Task 4 (No Host Header)")

    # 验证结果
    stored_params = redis_helper.get_host_params(host)
    print(f"\nStored Params for {host}: {stored_params}")
    
    expected_params = {
        "user_id", "type",       # from task 1
        "username", "password", "token", # from task 2
        "search", "filter",      # from task 3
        "extra"                  # from task 4
    }
    
    stored_set = set(stored_params)
    missing = expected_params - stored_set
    unexpected = stored_set - expected_params
    
    if not missing:
        print("\n[SUCCESS] All expected parameters were stored correctly!")
    else:
        print(f"\n[FAILURE] Missing parameters: {missing}")
        
    if unexpected:
        print(f"[INFO] Unexpected parameters found: {unexpected}")

    # 清理测试数据
    redis_helper.client.delete(redis_key)
    print("\nTest data cleaned up.")

if __name__ == "__main__":
    test_history_params_storage()
