import json
import time
from datetime import datetime
from pathlib import Path
from loguru import logger

class LLMAuditor:
    """
    LLM 交互审计记录器
    """
    def __init__(self, log_dir: str = "logs/llm_audit"):
        self.log_path = Path(log_dir)
        self.log_path.mkdir(parents=True, exist_ok=True)

    def record(self, agent_name: str, task_id: str, prompt: any, response: any):
        """记录单次交互"""
        log_file = self.log_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": agent_name,
            "task_id": task_id,
            "prompt": str(prompt),
            "response": str(response)
        }
        
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"无法写入 LLM 审计日志: {e}")

auditor = LLMAuditor()
