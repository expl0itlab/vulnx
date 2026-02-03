import subprocess
from typing import List, Dict, Any

class NiktoScanner:
    def scan(self, target: str) -> List[Dict[str, Any]]:
        command = ["nikto", "-h", target]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600
            )
            return self._parse_output(result.stdout)
        except Exception as e:
            return [{"error": f"Nikto scan failed: {str(e)}"}]

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        findings = []

        for line in output.splitlines():
            if line.startswith("+") and ("OSVDB" in line or "CVE" in line):
                findings.append({
                    "type": "web_vulnerability",
                    "description": line.lstrip("+ ").strip(),
                    "severity": "medium"
                })

        return findings
