import subprocess
from typing import List, Dict, Any


class NiktoScanner:
    """
    Runs Nikto against a target and parses human-readable output.
    Designed to work reliably with Nikto v2.5.x (Kali default).
    """

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
        except subprocess.TimeoutExpired:
            return [{
                "type": "error",
                "description": "Nikto scan timed out",
                "severity": "info"
            }]
        except Exception as e:
            return [{
                "type": "error",
                "description": f"Nikto scan failed: {str(e)}",
                "severity": "info"
            }]

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for line in output.splitlines():
            line = line.strip()

            if not line.startswith("+"):
                continue

            if any(line.startswith(f"+ {x}") for x in (
                "Target IP",
                "Target Hostname",
                "Target Port",
                "Start Time",
                "End Time",
                "Server:"
            )):
                continue

            description = line.lstrip("+ ").strip()

            if not description:
                continue

            findings.append({
                "type": "web_misconfiguration",
                "tool": "Nikto",
                "description": description,
                "severity": "medium"
            })

        return findings
