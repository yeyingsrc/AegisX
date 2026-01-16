from typing import List, Optional
from src.agents.manager.state import AgentState

class XSSState(AgentState):
    """
    XSS 专项攻击状态
    """
    # 漏洞分析进展
    potential_points: List[str]
    
    # 批量测试结果
    # 格式: [{"parameter": "q", "payload": "<script>...", "response": "...", "status": 200}]
    test_results: List[dict]
    
    # 决策逻辑
    next_step: str  # "found", "retry", "give_up"
    xss_retry_count: int
    analysis_feedback: List[str] # 记录分析器的反馈，用于指导下一轮生成
    
    # 攻击结果
    is_vulnerable: bool
    proof_of_concept: Optional[str]
