import time
from typing import List, Dict, Any

from .tools import NmapScanner, NiktoScanner, SQLMapScanner, ZAPScanner, Fuzzer
from .utils.helpers import Helpers
from .utils.output import OutputHandler


class VulnXScanner:
    def __init__(self, output_handler: OutputHandler, zap_config: Dict = None):
        self.output = output_handler
        self.helpers = Helpers()
        self.logger = self.helpers.setup_logging()

        self.nmap = NmapScanner()
        self.nikto = NiktoScanner()
        self.sqlmap = SQLMapScanner()

        zap_config = zap_config or {}
        self.zap = ZAPScanner(
            zap_host=zap_config.get("host", "localhost"),
            zap_port=zap_config.get("port", 8080),
            api_key=zap_config.get("api_key")
        )

        self.fuzzer = Fuzzer()

    def scan(
        self,
        target: str,
        scan_profile: str = "quick",
        tools: List[str] = None,
        **kwargs
    ) -> Dict[str, Any]:

        # Validate but DO NOT overwrite raw target
        validated = self.helpers.validate_target(target)
        validated_url = validated["url"]
        raw_target = target

        if tools is None:
            tools = {
                "quick": ["nmap", "nikto"],
                "deep": ["nmap", "nikto", "sqlmap", "fuzzer"],
                "full": ["nmap", "nikto", "sqlmap", "zap", "fuzzer"],
            }.get(scan_profile, ["nmap"])

        for tool in tools:
            try:
                if tool == "nmap":
                    for f in self.nmap.scan(raw_target, scan_profile):
                        if "error" not in f:
                            self.output.add_finding(
                                "Nmap",
                                "info",
                                "Open port",
                                f,
                            )

                elif tool == "nikto":
                    for f in self.nikto.scan(raw_target):
                        self.output.add_finding(
                            "Nikto",
                            "medium",
                            f["description"],
                            f,
                        )

                elif tool == "sqlmap":
                    for f in self.sqlmap.scan(validated_url):
                        self.output.add_finding(
                            "SQLMap",
                            "high",
                            f["description"],
                            f,
                        )

                elif tool == "zap":
                    if self.zap.is_accessible():
                        for f in self.zap.quick_scan(validated_url):
                            self.output.add_finding(
                                f.get("tool", "ZAP"),
                                f.get("severity", "info"),
                                f.get("description", ""),
                                f.get("details", {}),
                            )

                elif tool == "fuzzer":
                    for f in self.fuzzer.fuzz_endpoints(
                        validated_url,
                        kwargs.get("paths", []),
                    ):
                        self.output.add_finding(
                            "Fuzzer",
                            "info",
                            "Endpoint discovered",
                            f,
                        )

            except Exception as e:
                self.logger.error(f"{tool} failed: {e}")

        return {
            "status": "completed",
            "target": validated_url,
            "profile": scan_profile,
            "tools_used": tools,
            "findings_count": len(self.output.findings),
            "timestamp": time.time(),
        }
