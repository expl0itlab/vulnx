import subprocess
from typing import List, Dict


class NiktoScanner:
    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    def scan(self, target: str) -> List[Dict]:
        """
        Run Nikto against the target and parse findings.
        Uses raw target exactly as provided (http/https matters).
        """
        command = [
            "nikto",
            "-h",
            target,
            "-nointeractive",
            "-Display",
            "V",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return [{
                "description": "Nikto is not installed or not in PATH",
                "error": True,
            }]
        except subprocess.TimeoutExpired:
            return [{
                "description": "Nikto scan timed out",
                "error": True,
            }]

        findings = []

        for line in result.stdout.splitlines():
            line = line.strip()

            # Nikto findings always start with "+"
            if not line.startswith("+"):
                continue

            # Skip banners / metadata
            if any(
                skip in line.lower()
                for skip in [
                    "target ip",
                    "target hostname",
                    "target port",
                    "start time",
                    "nikto v",
                    "server:",
                ]
            ):
                continue

            findings.append({
                "description": line.lstrip("+ ").strip(),
                "raw": line,
            })

        return findings
