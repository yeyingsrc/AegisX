import httpx
import json
import asyncio
import difflib
from loguru import logger
from typing import Optional, List, Dict
from urllib.parse import parse_qsl
from src.config.settings import settings

class GenericExecutor:
    """
    通用探测执行引擎：支持 GET/POST 异步并发参数注入
    """
    def __init__(self, timeout: Optional[float] = None, proxies: Optional[str] = None, max_concurrency: Optional[int] = None):
        self.timeout = timeout or settings.SCAN_TIMEOUT
        self.proxies = proxies or settings.SCAN_PROXY
        self.max_concurrency = max_concurrency or settings.SCAN_MAX_CONCURRENCY
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

    async def execute_batch(self, 
                            target_url: str, 
                            method: str, 
                            test_cases: List[Dict], 
                            headers: Optional[dict] = None, 
                            original_body: Optional[str] = None,
                            original_response: Optional[str] = None) -> List[Dict]:
        """
        异步并发执行注入测试（受信号量限制）
        """
        if not test_cases:
            logger.warning("执行器收到空的测试用例列表，跳过执行")
            return []

        logger.info(f"开始执行异步探测任务 | 总计: {len(test_cases)} | 并发限制: {self.max_concurrency}")
        method = method.upper()
        target_base = target_url.split("?")[0]
        
        # 准备原始参数
        orig_query_params = {}
        if "?" in target_url:
            for p in target_url.split("?")[1].split("&"):
                if "=" in p:
                    k, v = p.split("=")
                    orig_query_params[k] = v

        # 准备原始 Body 数据
        orig_body_data = {}
        is_json = False
        
        # 预先处理 Headers，移除 Content-Length
        request_headers = (headers or {}).copy()
        # 移除长度相关的头，由 httpx 自动计算
        for h in list(request_headers.keys()):
            if h.lower() in ["content-length", "transfer-encoding"]:
                del request_headers[h]

        if method == "POST" and original_body:
            try:
                orig_body_data = json.loads(original_body)
                is_json = True
            except:
                for p in original_body.split("&"):
                    if "=" in p:
                        k, v = p.split("=")
                        orig_body_data[k] = v

        tasks = []
        async with httpx.AsyncClient(verify=False, headers=request_headers, proxy=self.proxies) as client:
            for test in test_cases:
                if not isinstance(test, dict):
                    continue
                    
                param_name = test.get("parameter")
                payload = test.get("payload")
                
                if not param_name or payload is None:
                    continue

                # 构造每个请求的专用数据
                current_query = orig_query_params.copy()
                current_body = orig_body_data.copy()
                current_url = target_base

                # 检查参数名是否本身就是包含占位符的模板 (RESTful 路径注入)
                if "{{PAYLOAD}}" in param_name:
                    current_url = param_name.replace("{{PAYLOAD}}", payload)
                elif param_name in current_query or method == "GET":
                    # 处理参数污染/注入 (payload 包含 & 和 =)
                    if isinstance(payload, str) and "&" in payload and "=" in payload:
                        try:
                            # 假设 payload 格式为 "val&new_param=val"
                            # 第一部分归属于当前参数
                            first_part = payload.split("&")[0]
                            current_query[param_name] = first_part
                            
                            # 解析剩余部分为新参数
                            remaining = payload[len(first_part)+1:]
                            extra_params = parse_qsl(remaining)
                            for k, v in extra_params:
                                current_query[k] = v
                        except Exception as e:
                            logger.warning(f"解析参数注入 Payload 失败: {e}, 回退到原始 Payload")
                            current_query[param_name] = payload
                    else:
                        current_query[param_name] = payload
                else:
                    # 对于 Body 数据 (非 JSON) 也可以做类似处理
                    if not is_json and isinstance(payload, str) and "&" in payload and "=" in payload:
                        try:
                            first_part = payload.split("&")[0]
                            current_body[param_name] = first_part
                            
                            remaining = payload[len(first_part)+1:]
                            extra_params = parse_qsl(remaining)
                            for k, v in extra_params:
                                current_body[k] = v
                        except Exception:
                            current_body[param_name] = payload
                    else:
                        current_body[param_name] = payload

                tasks.append(self._execute_with_semaphore(
                    client, method, current_url, current_query, current_body, is_json, param_name, payload, original_response=original_response
                ))

            # 并发执行所有请求
            results = await asyncio.gather(*tasks)
            
        return results

    async def _execute_with_semaphore(self, *args, **kwargs):
        """带并发控制的执行包装器"""
        async with self.semaphore:
            return await self._execute_single(*args, **kwargs)

    async def _execute_single(self, client, method, url, params, data, is_json, param_name, payload, original_response=None) -> Dict:
        """执行单个异步请求"""
        logger.debug(f"发送异步探测 | 方法: {method} | 参数: {param_name} | 并发槽: {self.max_concurrency - self.semaphore._value} | Payload: {payload}")
        try:
            if method == "GET":
                resp = await client.get(url, params=params, timeout=self.timeout)
            else:
                if is_json:
                    resp = await client.post(url, params=params, json=data, timeout=self.timeout)
                else:
                    resp = await client.post(url, params=params, data=data, timeout=self.timeout)
            
            # 计算差异值
            diff_stats = {}
            if original_response is not None:
                # 长度差异
                diff_stats["len_diff"] = len(resp.text) - len(original_response)
                # 相似度计算 (使用 quick_ratio 提高性能)
                # 如果响应过大，仅截取前 4KB 进行比较，避免 CPU 瓶颈
                orig_snippet = original_response[:4096]
                resp_snippet = resp.text[:4096]
                matcher = difflib.SequenceMatcher(None, orig_snippet, resp_snippet)
                diff_stats["similarity"] = round(matcher.quick_ratio(), 4)

            return {
                "parameter": param_name,
                "payload": payload,
                "response": resp.text,
                "status": resp.status_code,
                "elapsed": float(resp.elapsed.total_seconds()),
                **diff_stats
            }
        except httpx.ReadTimeout:
            # 捕获超时异常，视为可能的时间盲注成功
            logger.warning(f"请求超时 (可能触发了时间盲注) | 参数: {param_name} | Payload: {payload}")
            return {
                "parameter": param_name,
                "payload": payload,
                "response": "TIMEOUT_TRIGGERED_BLIND_SQLI",
                "status": 0,  # 使用 0 或特定状态码标识超时
                "elapsed": float(self.timeout)  # 将耗时标记为最大超时时间
            }
        except Exception as e:
            logger.exception(f"异步请求失败 ({param_name}): {e}")
            return {
                "parameter": param_name, "payload": payload,
                "response": f"Error: {str(e)}", "status": 0, "elapsed": 0.0
            }
