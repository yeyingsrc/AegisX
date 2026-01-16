from typing import List, Optional
from src.agents.manager.state import AgentState

class SQLiState(AgentState):
    """
    SQL 注入专项攻击状态
    """
    # 漏洞分析进展
    potential_points: List[str]
    db_type: Optional[str]
    
    # 多参数测试用例
    # 格式: [{"parameter": "id", "payload": "1'", "response": "...", "status": 200}]
    test_results: List[dict]
    
    
    # 决策逻辑
    next_step: str  # "found", "retry", "give_up"
    sqli_retry_count: int
    analysis_feedback: List[str] # 记录分析器的反馈，用于指导下一轮生成

    # 攻击结果
    is_vulnerable: bool
    proof_of_concept: Optional[str]  # 记录成功的参数和 Payload
