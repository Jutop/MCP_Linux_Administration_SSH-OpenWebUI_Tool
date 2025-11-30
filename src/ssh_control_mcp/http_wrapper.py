#!/usr/bin/env python3
"""
HTTP wrapper for SSH Control MCP Server
Provides a simple HTTP API for OpenWebUI to communicate with the MCP server
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
from ssh_control_mcp.server import create_server, ssh_conn, is_destructive_command
import ssh_control_mcp.server as server_module
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssh-http-wrapper")

app = Flask(__name__)
CORS(app)

# Load SSH config on startup
server_module.load_ssh_config()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "ssh-control-mcp"})

@app.route('/api/hosts', methods=['GET'])
def list_hosts():
    """List all configured SSH hosts."""
    try:
        if not server_module.SSH_HOSTS:
            return jsonify({"success": False, "error": "No hosts configured"})
        
        hosts = []
        for alias, config in server_module.SSH_HOSTS.items():
            hosts.append({
                "alias": alias,
                "hostname": config['hostname'],
                "username": config.get('username', 'root'),
                "port": config.get('port', 22),
                "description": config.get('description', '')
            })
        
        return jsonify({"success": True, "hosts": hosts})
    except Exception as e:
        logger.error(f"Error listing hosts: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/connect', methods=['POST'])
def connect():
    """Connect to a host."""
    try:
        data = request.json
        host = data.get('host')
        
        if not host:
            return jsonify({"success": False, "error": "No host specified"})
        
        result = ssh_conn.connect(host=host)
        return jsonify({"success": True, "message": result})
        
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/execute', methods=['POST'])
def execute():
    """Execute a command on the connected host."""
    try:
        data = request.json
        command = data.get('command')
        confirmed = data.get('confirmed', False)
        use_sudo = data.get('use_sudo', False)
        
        if not command:
            return jsonify({"success": False, "error": "No command provided"})
        
        # Auto-detect sudo
        if command.strip().startswith('sudo'):
            use_sudo = True
        
        # Check for destructive commands
        if is_destructive_command(command):
            if not confirmed:
                return jsonify({
                    "success": False,
                    "destructive": True,
                    "error": "Destructive command requires confirmation",
                    "warning": f"⚠️  WARNING: DESTRUCTIVE COMMAND DETECTED\n\nCommand: {command}\n\nThis command could:\n• Delete files or directories\n• Modify system configuration\n• Stop or restart services\n• Reboot/shutdown the system\n\nSet 'confirmed: true' to proceed."
                })
        
        # Get sudo password if needed
        sudo_password = None
        if use_sudo and ssh_conn.host_alias and ssh_conn.host_alias in server_module.SSH_HOSTS:
            sudo_password = server_module.SSH_HOSTS[ssh_conn.host_alias].get('password')
        
        # Execute command
        result = ssh_conn.execute_command(command, use_sudo=use_sudo, sudo_password=sudo_password)
        
        return jsonify({
            "success": result['success'],
            "command": result['command'],
            "hostname": result['hostname'],
            "exit_code": result['exit_code'],
            "stdout": result['stdout'],
            "stderr": result['stderr'],
            "used_sudo": result.get('used_sudo', False)
        })
        
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/disconnect', methods=['POST'])
def disconnect():
    """Disconnect from current host."""
    try:
        result = ssh_conn.disconnect()
        return jsonify({"success": True, "message": result})
    except Exception as e:
        logger.error(f"Disconnect error: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/status', methods=['GET'])
def status():
    """Get connection status."""
    try:
        if ssh_conn.is_connected():
            host_info = ssh_conn.host_alias or ssh_conn.hostname
            message = f"Connected to: {host_info}"
            if ssh_conn.host_alias and ssh_conn.hostname:
                message += f" ({ssh_conn.hostname})"
            
            return jsonify({
                "success": True,
                "connected": True,
                "host": ssh_conn.host_alias,
                "hostname": ssh_conn.hostname,
                "message": message
            })
        else:
            return jsonify({
                "success": True,
                "connected": False,
                "message": "Not connected to any host"
            })
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    logger.info("Starting SSH Control HTTP Wrapper on port 3000")
    app.run(host='0.0.0.0', port=3000, debug=False)
