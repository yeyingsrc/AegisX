import os
import sys
import uuid

# 将项目根目录添加到 sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.report_generator import ReportGenerator

def test_manual_report_generation():
    print("=== 测试手动生成报告 ===")
    
    gen = ReportGenerator(output_dir="reports_test")
    request_id = str(uuid.uuid4())[:8]
    
    mock_findings = [
        {
            "type": "SQL Injection",
            "url": "http://example.com/api/user?id=1&name=test&token=abc",
            "parameter": "id",
            "payload": "1' OR '1'='1",
            "evidence": "Found error in response",
            "original_request": {
                "method": "GET",
                "url": "http://example.com/api/user?id=1&name=test&token=abc",
                "headers": {"User-Agent": "WebAgent/1.0", "Cookie": "session=xyz"},
                "body": None
            }
        },
        {
            "type": "Reflected XSS",
            "url": "http://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected in body",
            "original_request": {
                "method": "POST",
                "url": "http://example.com/search",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "q=test&category=fruit"
            }
        }
    ]
    
    report_path = gen.generate(mock_findings, request_id)
    print(f"报告已生成: {report_path}")
    
    if os.path.exists(report_path):
        print("验证成功: 报告文件存在。")
        with open(report_path, "r", encoding="utf-8") as f:
            print("--- 报告内容预览 ---")
            print(f.read()[:200] + "...")
    else:
        print("验证失败: 报告文件未生成。")

if __name__ == "__main__":
    import os
    test_manual_report_generation()
