import httpx
import json
import asyncio
import difflib
import re
import urllib.parse
from loguru import logger
from typing import Optional, List, Dict, Any
from src.config.settings import settings

class StructuredExecutor:
    """
    重构后的结构化执行器：支持基于模板和占位符的并发探测。
    数据包结构参考 AgentState 字典形式。
    """
    def __init__(self, timeout: Optional[float] = None, proxies: Optional[str] = None, max_concurrency: Optional[int] = None):
        self.timeout = timeout or settings.SCAN_TIMEOUT
        self.proxies = proxies or settings.SCAN_PROXY
        self.max_concurrency = max_concurrency or settings.SCAN_MAX_CONCURRENCY
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

    async def execute_structured(self, 
                                 structured_packet: Dict[str, Any], 
                                 original_response: Optional[str] = None) -> List[Dict]:
        """
        执行结构化数据包中的所有测试用例。
        :param structured_packet: 包含 request (template) 和 test_cases 的字典。
        :param original_response: 原始响应体，用于计算差异。
        """
        request_template = structured_packet.get("request", {})
        test_cases = structured_packet.get("test_cases", [])
        
        if not test_cases:
            logger.warning("结构化执行器收到空的测试用例列表")
            return []

        method = request_template.get("method", "GET").upper()
        target_url_template = request_template.get("target_url", "")
        headers_template = request_template.get("headers", {})
        body_template = request_template.get("body")

        # 1. 预处理：提取所有合法的 {{}} 占位符并过滤测试用例
        # 只从 request_template 中提取占位符，确保测试点确实存在于请求模板中
        placeholders = re.findall(r'\{\{(.*?)\}\}', json.dumps(request_template))
        valid_placeholders = {f"{{{{{val}}}}}" for val in placeholders}
        placeholder_map = {f"{{{{{val}}}}}": val for val in placeholders}

        filtered_test_cases = []
        for test in test_cases:
            param_placeholder = test.get("parameter")
            if param_placeholder and param_placeholder in valid_placeholders:
                filtered_test_cases.append(test)
            else:
                logger.warning(f"跳过无效或未定义的占位符: {param_placeholder}")

        if not filtered_test_cases:
            logger.warning("没有合法的测试用例可执行")
            return []

        # 2. 预处理 Headers，移除长度相关的头
        clean_headers_template = headers_template.copy()
        for h in list(clean_headers_template.keys()):
            if h.lower() in ["content-length", "transfer-encoding"]:
                del clean_headers_template[h]

        tasks = []
        async with httpx.AsyncClient(verify=False, proxy=self.proxies) as client:
            for test in filtered_test_cases:
                param_placeholder = test.get("parameter")
                payloads = test.get("payload", [])
                
                if not isinstance(payloads, list):
                    payloads = [payloads]

                for payload in payloads:
                    # 1. 构造当前请求的具体数据
                    # 将当前正在测试的占位符替换为 payload，将其他所有占位符还原为原始值
                    
                    current_url = target_url_template
                    current_headers = clean_headers_template.copy()
                    current_body = body_template

                    # 替换 URL
                    current_url = self._replace_logic(current_url, param_placeholder, payload, placeholder_map, is_url=True)
                    
                    # 替换 Headers (Headers 通常不需要 URL 编码)
                    for k, v in current_headers.items():
                        if isinstance(v, str):
                            current_headers[k] = self._replace_logic(v, param_placeholder, payload, placeholder_map, is_url=False)
                    
                    # 替换 Body
                    if current_body:
                        content_type = clean_headers_template.get("Content-Type", "").lower()
                        is_form = "application/x-www-form-urlencoded" in content_type
                        # 只有是 application/x-www-form-urlencoded 时才进行 URL 编码，其他（JSON, XML, Plain 等）一律不编码
                        current_body = self._replace_logic(current_body, param_placeholder, payload, placeholder_map, is_url=is_form)

                    tasks.append(self._execute_with_semaphore(
                        client, method, current_url, current_headers, current_body, 
                        param_placeholder, payload, original_response
                    ))

            # 并发执行所有请求
            results = await asyncio.gather(*tasks)
            
        return results

    async def _execute_with_semaphore(self, *args, **kwargs):
        """带并发控制的执行包装器"""
        async with self.semaphore:
            return await self._execute_single(*args, **kwargs)

    async def _execute_single(self, client, method, url, headers, body, param_name, payload, original_response=None) -> Dict:
        """执行单个异步请求"""
        logger.debug(f"发送结构化探测 | 方法: {method} | URL: {url} | Body: {body[:200] if body else 'None'} | Headers: {headers} | 参数点: {param_name} | Payload: {payload}")
        try:
            # 根据 body 类型决定发送方式
            # 注意：对于 Fuzz 场景，我们使用 content 而不是 json/data，以防止 httpx 自动对 payload 进行 urlencode
            kwargs = {"url": url, "headers": headers, "timeout": self.timeout}
            
            if body:
                if isinstance(body, str):
                    kwargs["content"] = body
                else:
                    kwargs["content"] = json.dumps(body)

            if method == "GET":
                # 对于 GET 请求，如果 URL 中已经包含了编码后的参数，我们直接使用 url 字符串
                # httpx.get(url) 会保持 URL 原样，不会再次编码已经编码的部分
                resp = await client.get(**kwargs)
            elif method == "POST":
                resp = await client.post(**kwargs)
            else:
                resp = await client.request(method, **kwargs)
            
            # 计算差异值
            diff_stats = {}
            if original_response is not None:
                diff_stats["len_diff"] = len(resp.text) - len(original_response)
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
            logger.warning(f"结构化请求超时 | 参数点: {param_name} | Payload: {payload}")
            return {
                "parameter": param_name,
                "payload": payload,
                "response": "TIMEOUT_TRIGGERED",
                "status": 0,
                "elapsed": float(self.timeout),
                "len_diff": 0,
                "similarity": 0.0
            }
        except Exception as e:
            logger.exception(f"结构化请求失败 ({param_name}): {e}")
            return {
                "parameter": param_name, "payload": payload,
                "response": f"Error: {str(e)}", "status": 0, "elapsed": 0.0,
                "len_diff": 0, "similarity": 0.0
            }

    def _replace_logic(self, text: str, active_placeholder: str, active_payload: str, placeholder_map: Dict[str, str], is_url: bool = True) -> str:
        """
        内部替换逻辑：支持占位符还原和根据场景选择编码策略。
        """
        if not text: return text
        
        # 1. 确定编码策略
        if is_url:
            # URL 和 Form 场景：进行 URL 编码，但保留安全字符 (&=/)
            safe_chars = "&=/"
            encoded_payload = urllib.parse.quote(str(active_payload), safe=safe_chars)
        else:
            # JSON 和 Header 场景：不进行 URL 编码，直接使用原始 Payload
            encoded_payload = str(active_payload)
        
        # 2. 替换当前测试点
        res = text.replace(active_placeholder, encoded_payload)
        
        # 3. 将其他所有占位符还原为原始值
        for ph, orig in placeholder_map.items():
            if ph in res and ph != active_placeholder:
                res = res.replace(ph, str(orig))
        return res
