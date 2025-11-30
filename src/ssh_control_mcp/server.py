#!/usr/bin/env python3
"""
SSH Control MCP Server
Allows controlling Linux hosts via SSH with safety checks for destructive commands.
"""

import asyncio
import logging
import re
import yaml
from pathlib import Path
from typing import Any, Optional
import paramiko
from mcp.server import Server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
from mcp.server.stdio import stdio_server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssh-control-mcp")

# Load configuration
CONFIG_PATH = Path("/app/config.yaml")
SSH_HOSTS = {}

# Destructive command patterns - these require confirmation
DESTRUCTIVE_PATTERNS = [
    r'\brm\b.*-[rf]+',  # rm with -r or -f flags
    r'\brm\b.*/',  # rm with directory paths
    r'\bdd\b',  # dd command
    r'\bmkfs\b',  # filesystem formatting
    r'\bformat\b',
    r'\bfdisk\b',
    r'\bparted\b',
    r'\bcryptsetup\b.*luksFormat',
    r'\b:>\s*/',  # truncate files
    r'\bshred\b',
    r'\bwipefs\b',
    r'\b>\s*/dev/',  # redirect to devices
    r'\bchmod\b.*777',  # overly permissive chmod
    r'\bchown\b',  # any chown
    r'\bkill\b.*-9',  # force kill
    r'\bkillall\b',
    r'\bpkill\b',
    r'\bsystemctl\b.*(stop|disable|mask|restart)',
    r'\bservice\b.*(stop|disable|restart)',
    r'\bapt-get\b.*(remove|purge|autoremove)',
    r'\bapt\b.*(remove|purge|autoremove)',
    r'\byum\b.*(remove|erase)',
    r'\bdnf\b.*(remove|erase)',
    r'\bpacman\b.*-R',
    r'\bsnap\b.*remove',
    r'\bdocker\b.*(rm|rmi|system prune)',
    r'\biptables\b.*-F',  # flush firewall rules
    r'\bufw\b.*disable',
    r'\binit\b.*0',  # shutdown
    r'\bshutdown\b',
    r'\breboot\b',
    r'\bhalt\b',
    r'\bpoweroff\b',
    r'\buserdel\b',  # delete user
    r'\busermod\b',  # modify user
    r'\bgroupdel\b',  # delete group
    r'\bmv\b.*/',  # move files/directories
    r'\btruncate\b',
    r'\bcrontab\b.*-r',  # remove cron jobs
]

def load_ssh_config():
    """Load SSH host configurations from config file."""
    global SSH_HOSTS
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)
                SSH_HOSTS = config.get('hosts', {})
                logger.info(f"Loaded {len(SSH_HOSTS)} host configurations")
        else:
            logger.warning(f"Config file not found at {CONFIG_PATH}")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")


def is_destructive_command(command: str) -> bool:
    """Check if a command is potentially destructive."""
    command_lower = command.lower().strip()
    
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command_lower):
            return True
    
    return False


class SSHConnection:
    """Manages SSH connection to a remote host."""
    
    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None
        self.hostname: Optional[str] = None
        self.host_alias: Optional[str] = None
        
    def connect(self, host: str) -> str:
        """Establish SSH connection to a host using config file or direct hostname."""
        try:
            # Check if host is an alias in config
            if host in SSH_HOSTS:
                config = SSH_HOSTS[host]
                hostname = config['hostname']
                port = config.get('port', 22)
                username = config.get('username', 'root')
                password = config.get('password')
                description = config.get('description', '')
                self.host_alias = host
            else:
                # Treat as direct hostname (not recommended, but fallback)
                hostname = host
                port = 22
                username = 'root'
                password = None
                description = ''
                self.host_alias = None
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": hostname,
                "port": port,
                "username": username,
                "timeout": 10,
                "look_for_keys": False,  # Disable key-based auth
                "allow_agent": False,     # Disable SSH agent
            }
            
            if password:
                connect_kwargs["password"] = password
            else:
                raise Exception(f"No password found for host '{host}' in config")
                
            self.client.connect(**connect_kwargs)
            self.hostname = hostname
            
            msg = f"Successfully connected to {host}"
            if description:
                msg += f" ({description})"
            logger.info(msg)
            return msg
            
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            raise Exception(f"SSH connection failed: {str(e)}")
    
    def execute_command(self, command: str, use_sudo: bool = False, sudo_password: Optional[str] = None) -> dict[str, Any]:
        """Execute a command on the remote host."""
        if not self.client or not self.hostname:
            raise Exception("Not connected to any host. Please connect first.")
        
        try:
            # Prepare the command with sudo if requested
            if use_sudo:
                if command.strip().startswith('sudo'):
                    # Already has sudo
                    exec_command = command
                else:
                    # Add sudo prefix
                    exec_command = f"sudo -S {command}"
            else:
                exec_command = command
            
            stdin, stdout, stderr = self.client.exec_command(exec_command, timeout=30, get_pty=use_sudo)
            
            # If using sudo, send password
            if use_sudo and sudo_password:
                stdin.write(sudo_password + '\n')
                stdin.flush()
            
            exit_code = stdout.channel.recv_exit_status()
            
            stdout_text = stdout.read().decode('utf-8', errors='replace')
            stderr_text = stderr.read().decode('utf-8', errors='replace')
            
            # Remove password prompt from output if present
            if use_sudo and '[sudo]' in stdout_text:
                stdout_text = '\n'.join([line for line in stdout_text.split('\n') if '[sudo]' not in line])
            
            return {
                "hostname": self.hostname,
                "command": command,
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "success": exit_code == 0,
                "used_sudo": use_sudo
            }
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise Exception(f"Failed to execute command: {str(e)}")
    
    def disconnect(self) -> str:
        """Close the SSH connection."""
        if self.client:
            hostname = self.host_alias or self.hostname
            self.client.close()
            self.client = None
            self.hostname = None
            self.host_alias = None
            logger.info(f"Disconnected from {hostname}")
            return f"Disconnected from {hostname}"
        return "No active connection"
    
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self.client is not None and self.hostname is not None


# Global SSH connection instance
ssh_conn = SSHConnection()


def create_server() -> Server:
    """Create and configure the MCP server."""
    server = Server("ssh-control-mcp")
    
    # Load SSH configuration on startup
    load_ssh_config()
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List available SSH control tools."""
        # Build host list for description
        host_list = ", ".join(SSH_HOSTS.keys()) if SSH_HOSTS else "No hosts configured"
        
        return [
            Tool(
                name="ssh_list_hosts",
                description=f"List all configured SSH hosts from config file. Available hosts: {host_list}",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="ssh_connect",
                description="Connect to a Linux host via SSH using credentials from config.yaml. Use the host alias (e.g., 'vm1', 'vm2') from your config file.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": f"Host alias from config file. Available: {host_list}"
                        }
                    },
                    "required": ["host"]
                }
            ),
            Tool(
                name="ssh_execute",
                description="Execute a command on the connected Linux host. IMPORTANT: Destructive commands (rm -rf, dd, shutdown, etc.) ALWAYS require explicit confirmation before execution. Supports sudo commands.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to execute. Can start with 'sudo' for elevated privileges."
                        },
                        "confirmed": {
                            "type": "boolean",
                            "description": "REQUIRED: Set to true to confirm execution of destructive commands. You will be prompted first.",
                            "default": False
                        },
                        "use_sudo": {
                            "type": "boolean",
                            "description": "Set to true to execute with sudo privileges (will use password from config)",
                            "default": False
                        }
                    },
                    "required": ["command"]
                }
            ),
            Tool(
                name="ssh_disconnect",
                description="Disconnect from the current SSH session.",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="ssh_status",
                description="Check the current SSH connection status.",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: Any) -> list[TextContent]:
        """Handle tool execution requests."""
        
        try:
            if name == "ssh_list_hosts":
                if not SSH_HOSTS:
                    return [TextContent(type="text", text="No hosts configured in config.yaml")]
                
                output = "Configured SSH Hosts:\n\n"
                for alias, config in SSH_HOSTS.items():
                    output += f"  {alias}:\n"
                    output += f"    Hostname: {config['hostname']}\n"
                    output += f"    Username: {config.get('username', 'root')}\n"
                    output += f"    Port: {config.get('port', 22)}\n"
                    if config.get('description'):
                        output += f"    Description: {config['description']}\n"
                    output += "\n"
                
                return [TextContent(type="text", text=output)]
            
            elif name == "ssh_connect":
                host = arguments.get("host")
                
                if not host:
                    return [TextContent(type="text", text="Error: No host specified")]
                
                result = ssh_conn.connect(host=host)
                return [TextContent(type="text", text=result)]
            
            elif name == "ssh_execute":
                command = arguments.get("command")
                confirmed = arguments.get("confirmed", False)
                use_sudo = arguments.get("use_sudo", False)
                
                if not command:
                    return [TextContent(type="text", text="Error: No command provided")]
                
                # Auto-detect sudo in command
                if command.strip().startswith('sudo'):
                    use_sudo = True
                
                # Check if command is destructive - ALWAYS require confirmation
                if is_destructive_command(command):
                    if not confirmed:
                        warning = f"⚠️  WARNING: DESTRUCTIVE COMMAND DETECTED\n\n"
                        warning += f"Command: {command}\n\n"
                        warning += "This command could:\n"
                        warning += "• Delete files or directories\n"
                        warning += "• Modify system configuration\n"
                        warning += "• Stop or restart services\n"
                        warning += "• Reboot/shutdown the system\n"
                        warning += "• Remove packages or users\n"
                        warning += "• Change permissions or ownership\n\n"
                        warning += "❌ CONFIRMATION REQUIRED\n\n"
                        warning += "To execute this command, you MUST confirm by:\n"
                        warning += "Setting 'confirmed: true' in the tool parameters\n\n"
                        warning += "⚠️  Please review the command carefully before confirming!"
                        
                        return [TextContent(type="text", text=warning)]
                
                # Get sudo password if needed
                sudo_password = None
                if use_sudo and ssh_conn.host_alias and ssh_conn.host_alias in SSH_HOSTS:
                    sudo_password = SSH_HOSTS[ssh_conn.host_alias].get('password')
                
                # Execute the command
                result = ssh_conn.execute_command(command, use_sudo=use_sudo, sudo_password=sudo_password)
                
                # Format the response
                output = f"Command: {result['command']}\n"
                output += f"Host: {result['hostname']}\n"
                if result.get('used_sudo'):
                    output += f"Executed with: sudo\n"
                output += f"Exit Code: {result['exit_code']}\n\n"
                
                if result['stdout']:
                    output += f"STDOUT:\n{result['stdout']}\n"
                
                if result['stderr']:
                    output += f"\nSTDERR:\n{result['stderr']}\n"
                
                if not result['success']:
                    output += f"\n⚠️  Command failed with exit code {result['exit_code']}"
                
                return [TextContent(type="text", text=output)]
            
            elif name == "ssh_disconnect":
                result = ssh_conn.disconnect()
                return [TextContent(type="text", text=result)]
            
            elif name == "ssh_status":
                if ssh_conn.is_connected():
                    host_info = ssh_conn.host_alias or ssh_conn.hostname
                    status = f"Connected to: {host_info}"
                    if ssh_conn.host_alias and ssh_conn.hostname:
                        status += f" ({ssh_conn.hostname})"
                else:
                    status = "Not connected to any host"
                
                return [TextContent(type="text", text=status)]
            
            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]
        
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    return server


async def main():
    """Run the MCP server."""
    logger.info("Starting SSH Control MCP Server")
    server = create_server()
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
