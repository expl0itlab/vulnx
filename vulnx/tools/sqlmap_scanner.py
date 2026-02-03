import subprocess
import os
import json
from typing import List, Dict, Any

class SQLMapScanner:
    def scan(self, target: str, level: int = 1) -> List[Dict[str, Any]]:
        output_dir = "/tmp/sqlmap_output"
        os.makedirs(output_dir, exist_ok=True)

        command = [
            "sqlmap",
            "-u", target,
            "--level", str(level),
            "--batch",
            "--output-dir", output_dir,
            "--flush-session"
        ]

        try:
            subprocess.run(command, capture_output=True, text=True, timeout=900)
            return self._parse_output(output_dir)
        except Exception as e:
            return [{"error": f"SQLMap scan failed: {str(e)}"}]

    def _parse_output(self, output_dir: str) -> List[Dict[str, Any]]:
        findings = []

        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".json"):
                    try:
                        with open(os.path.join(root, file)) as f:
                            data = json.load(f)
                            findings.append({
                                "type": "sql_injection",
                                "description": "SQL injection vulnerability detected",
                                "severity": "high",
                                "details": data
                            })
                    except Exception:
                        continue

        return findings
