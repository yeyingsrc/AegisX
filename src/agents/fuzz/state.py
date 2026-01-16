from typing import Annotated, List, Dict, Any, Optional
import operator
from src.agents.manager.state import AgentState

class FuzzState(AgentState):
    """
    Fuzz 模糊测试状态
    """
    # 扫描上下文
    potential_points: List[str]  # 待测试参数列表
    history_params: List[str]    # 从 Redis 获取的历史参数
    
    # 执行状态
    test_results: List[Dict]     # 存储 Executor 的测试结果
    analysis_feedback: List[str] # Analyzer 返回的反馈
    fuzz_retry_count: int             # 当前重试次数
    
    # 结果输出
    # findings 已经在 AgentState 中定义，这里不需要重复定义，或者保持一致
    status: str                  # 任务状态: running, completed, failed
    
    next_step: str

