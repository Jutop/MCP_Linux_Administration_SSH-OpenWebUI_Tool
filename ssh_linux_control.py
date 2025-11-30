"""
title: SSH Linux Control
author: open-webui
author_url: https://github.com/open-webui
funding_url: https://github.com/open-webui
version: 1.0.0
license: MIT
description: Control Linux VMs via SSH with safety checks for destructive commands
required_open_webui_version: 0.3.9
"""

import requests
from pydantic import Field


class Tools:
    def __init__(self):
        # Use container name since OpenWebUI is containerized
        self.api_url = "http://ssh-control-mcp:3000"

    def _make_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make HTTP request to the MCP server."""
        try:
            url = f"{self.api_url}{endpoint}"
            if method == "GET":
                response = requests.get(url, timeout=30)
            else:
                response = requests.post(url, json=data, timeout=30)
            
            return response.json()
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Cannot connect to SSH Control MCP server. Ensure the container is running."}
        except Exception as e:
            return {"success": False, "error": f"Request error: {str(e)}"}

    def ssh_list_hosts(self) -> str:
        """
        List all configured SSH hosts from config file.
        """
        result = self._make_request("GET", "/api/hosts")
        
        if not result.get("success"):
            return f"Error: {result.get('error', 'Unknown error')}"
        
        hosts = result.get("hosts", [])
        if not hosts:
            return "No hosts configured in config.yaml"
        
        output = "Configured SSH Hosts:\n\n"
        for host in hosts:
            output += f"  {host['alias']}:\n"
            output += f"    Hostname: {host['hostname']}\n"
            output += f"    Username: {host['username']}\n"
            output += f"    Port: {host['port']}\n"
            if host.get('description'):
                output += f"    Description: {host['description']}\n"
            output += "\n"
        
        return output

    def ssh_connect(
        self, 
        host: str = Field(..., description="Host alias from config file (e.g., 'vm1', 'vm2')")
    ) -> str:
        """
        Connect to a Linux host via SSH using credentials from config.
        """
        result = self._make_request("POST", "/api/connect", {"host": host})
        
        if result.get("success"):
            return result.get("message", "Connected successfully")
        else:
            return f"Error: {result.get('error', 'Connection failed')}"

    def ssh_execute(
        self, 
        command: str = Field(..., description="The shell command to execute"), 
        confirmed: bool = False,
        use_sudo: bool = False
    ) -> str:
        """
        Execute a command on the connected Linux host.
        IMPORTANT: Destructive commands (rm -rf, shutdown, etc.) require confirmed=True
        """
        result = self._make_request("POST", "/api/execute", {
            "command": command,
            "confirmed": confirmed,
            "use_sudo": use_sudo
        })
        
        if result.get("destructive"):
            return result.get("warning", "Destructive command requires confirmation")
        
        if not result.get("success"):
            return f"Error: {result.get('error', 'Command failed')}"
        
        output = f"Command: {result.get('command')}\n"
        output += f"Host: {result.get('hostname')}\n"
        if result.get('used_sudo'):
            output += f"Executed with: sudo\n"
        output += f"Exit Code: {result.get('exit_code')}\n\n"
        
        if result.get('stdout'):
            output += f"STDOUT:\n{result['stdout']}\n"
        
        if result.get('stderr'):
            output += f"\nSTDERR:\n{result['stderr']}\n"
        
        if result.get('exit_code') != 0:
            output += f"\n⚠️  Command failed with exit code {result.get('exit_code')}"
        
        return output

    def ssh_disconnect(self) -> str:
        """
        Disconnect from the current SSH session.
        """
        result = self._make_request("POST", "/api/disconnect")
        
        if result.get("success"):
            return result.get("message", "Disconnected")
        else:
            return f"Error: {result.get('error', 'Disconnect failed')}"

    def ssh_status(self) -> str:
        """
        Check the current SSH connection status.
        """
        result = self._make_request("GET", "/api/status")
        
        if result.get("success"):
            return result.get("message", "Unknown status")
        else:
            return f"Error: {result.get('error', 'Status check failed')}"

    # Convenience methods for common operations
    
    def check_disk_space(
        self, 
        host: str = Field(..., description="Host alias to connect to")
    ) -> str:
        """
        Connect to a host and check disk space.
        """
        connect_result = self.ssh_connect(host)
        if "Successfully connected" in connect_result:
            return self.ssh_execute("df -h")
        return connect_result

    def check_memory(
        self, 
        host: str = Field(..., description="Host alias to connect to")
    ) -> str:
        """
        Connect to a host and check memory usage.
        """
        connect_result = self.ssh_connect(host)
        if "Successfully connected" in connect_result:
            return self.ssh_execute("free -h")
        return connect_result

    def check_uptime(
        self, 
        host: str = Field(..., description="Host alias to connect to")
    ) -> str:
        """
        Connect to a host and check system uptime.
        """
        connect_result = self.ssh_connect(host)
        if "Successfully connected" in connect_result:
            return self.ssh_execute("uptime")
        return connect_result

    def list_services(
        self, 
        host: str = Field(..., description="Host alias to connect to")
    ) -> str:
        """
        Connect to a host and list running services.
        """
        connect_result = self.ssh_connect(host)
        if "Successfully connected" in connect_result:
            return self.ssh_execute("systemctl list-units --type=service --state=running")
        return connect_result

    def update_system(
        self, 
        host: str = Field(..., description="Host alias to connect to"),
        confirmed: bool = False
    ) -> str:
        """
        Update system packages on a host (requires sudo).
        """
        if not confirmed:
            return "⚠️  System update requires confirmation. Set confirmed=True to proceed."
        
        connect_result = self.ssh_connect(host)
        if "Successfully connected" in connect_result:
            return self.ssh_execute("apt update && apt upgrade -y", use_sudo=True, confirmed=True)
        return connect_result
