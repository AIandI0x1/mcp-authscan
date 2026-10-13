"""MCP Server Security Scanner - VATA Methodology"""
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
        self.check_tools_call()  # CRITICAL - actual exploitation
        self.check_tools_list()  # MEDIUM - information disclosure
        self.check_initialize()  # INFO - normal handshake
        self.check_cors()
        return self.findings
    
    def check_tools_call(self):
        """CHECK: Can we EXECUTE tools without auth? (CRITICAL if yes)"""
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "test", "arguments": {}},
                "id": 1
            }
            resp = requests.post(f"{self.url}/message", json=payload, timeout=5)
            
            # If we get 200 with result, we can execute without auth = CRITICAL
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    self.findings.append({
                        "endpoint": "tools/call",
                        "severity": "CRITICAL",
                        "issue": "Unauthenticated tool execution possible"
                    })
        except:
            pass
    
    def check_tools_list(self):
        """CHECK: Can we LIST tools without auth? (MEDIUM - info disclosure)"""
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
                        "endpoint": "tools/list",
                        "severity": "MEDIUM",
                        "issue": "Tool enumeration without auth (information disclosure)"
                    })
        except:
            pass
    
    def check_initialize(self):
        """CHECK: Initialize endpoint (INFO - expected to work)"""
        try:
            resp = requests.post(
                f"{self.url}/message",
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-01-15",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-authscan", "version": "1.0"}
                    },
                    "id": 1
                },
                timeout=5
            )
            
            # Initialize returning data is NORMAL - no finding
            # Initialize returning 401 means auth is required - that's good
            if resp.status_code == 401:
                self.findings.append({
                    "endpoint": "initialize",
                    "severity": "PASS",
                    "issue": "Properly requires authentication"
                })
        except:
            pass
    
    def check_cors(self):
        """CHECK: CORS wildcard (HIGH - enables cross-origin attacks)"""
        try:
            resp = requests.options(f"{self.url}/message", timeout=5)
            cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            if cors_origin == "*":
                self.findings.append({
                    "endpoint": "CORS",
                    "severity": "HIGH",
                    "issue": "CORS wildcard allows any origin"
                })
        except:
            pass
