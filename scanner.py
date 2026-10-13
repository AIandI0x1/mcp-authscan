"""MCP Server Security Scanner"""
import requests
import json
from typing import List, Dict

class MCPScanner:
    """Scan MCP servers for security issues"""
    
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Run all security checks"""
        self.check_sse_auth()
        self.check_message_auth()
        self.check_tools_list_auth()
        self.check_cors()
        return self.findings
    
    def check_sse_auth(self):
        """Check if /sse requires auth"""
        try:
            resp = requests.get(f"{self.url}/sse", timeout=5)
            if resp.status_code == 200:
                self.findings.append({
                    "endpoint": "/sse",
                    "severity": "CRITICAL",
                    "issue": "No authentication required"
                })
        except:
            pass
    
    def check_message_auth(self):
        """Check if /message requires auth"""
        try:
            resp = requests.post(
                f"{self.url}/message",
                json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    self.findings.append({
                        "endpoint": "/message",
                        "severity": "CRITICAL",
                        "issue": "No authentication required"
                    })
        except:
            pass
    
    def check_tools_list_auth(self):
        """Check if tools/list requires auth"""
        try:
            resp = requests.post(
                f"{self.url}/tools/list",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data and data["result"]:
                    self.findings.append({
                        "endpoint": "/tools/list",
                        "severity": "HIGH",
                        "issue": "Tool enumeration without auth"
                    })
        except:
            pass
    
    def check_cors(self):
        """Check CORS configuration"""
        try:
            resp = requests.options(f"{self.url}/message", timeout=5)
            cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            if cors_origin == "*":
                self.findings.append({
                    "endpoint": "CORS",
                    "severity": "HIGH",
                    "issue": "CORS wildcard allowed"
                })
        except:
            pass

def probe_unauthenticated(url):
    """Run unauthenticated discovery probes"""
    from tests.test_unauthenticated_probes import UnauthenticatedProbeTest
    tester = UnauthenticatedProbeTest(url)
    return tester.run_all()
