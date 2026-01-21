import json
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.utils.auditor import auditor
from src.core.llm.service import create_audited_llm
from loguru import logger

class GenericStrategist:
    """
    通用策略生成引擎：根据不同的提示词生成特定漏洞的测试用例
    """
    def __init__(self):
        self.audited_llm = create_audited_llm(
            model_name=settings.MODEL_NAME_WORKER,
            api_key=settings.OPENAI_API_KEY,
            api_base=settings.OPENAI_API_BASE,
            model_kwargs={"response_format": {"type": "json_object"}}
        )

    def generate(self, vuln_type: str, system_prompt: str, user_context: dict, request_id: str, project_name: str = "Default") -> dict:
        """
        通用生成方法：返回符合 StructuredExecutor 要求的结构化数据包
        """
        # 使用普通的字符串拼接，避免在构建阶段使用 f-string 导致花括号转义混乱
        user_content = "### 目标上下文\n"
        user_content += "原始请求: {full_request_json}\n"
        user_content += "潜在探测点: {points_str}\n"
        
        feedback = user_context.get("feedback")
        if feedback:
            user_content += "分析反馈: {feedback_str}\n"
        
        history_results = user_context.get("history_results")
        if history_results:
            user_content += "历史探测结果汇总:\n{history_results_json}\n"

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", user_content)
        ])
        
        # 准备所有输入变量，集中进行 JSON 序列化
        points = user_context.get('points', [])
        if points and isinstance(points[0], dict):
            points_str = "\n".join([f"- 参数: {p['name']}, 原始值: {p['value']}, 类型: {p['type']}, 建议占位符: {p['placeholder']}" for p in points])
        else:
            points_str = ", ".join(points)

        inputs = {
            "full_request_json": json.dumps(user_context.get('full_request', {}), ensure_ascii=False),
            "points_str": points_str,
            "feedback_str": str(feedback) if feedback else "",
            "history_results_json": json.dumps(history_results, ensure_ascii=False) if history_results else "[]"
        }
        
        chain = prompt | self.audited_llm.llm
        
        try:
            response = self.audited_llm.invoke(
                chain=chain,
                inputs=inputs,
                agent_name=f"{vuln_type}_Strategist",
                task_id=request_id,
                prompt_template=prompt,
                project_name=project_name
            )
            
            data = json.loads(response.content)
            
            # 兼容性处理：确保返回结构符合 StructuredExecutor 要求
            structured_packet = {
                "request": data.get("request", user_context.get("full_request", {})),
                "test_cases": data.get("test_cases", [])
            }
            
            logger.info(f"[{vuln_type}] 策略生成完成 | 探测点数量: {len(structured_packet['test_cases'])}")
            return structured_packet
        except Exception as e:
            logger.error(f"[{vuln_type}] 生成 Payload 失败: {e}")
            return {"request": user_context.get("full_request", {}), "test_cases": []}
