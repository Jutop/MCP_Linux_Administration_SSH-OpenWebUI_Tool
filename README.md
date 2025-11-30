# MCP Server - SSH Linux Control for OpenWebUI

Control your Linux VMs via SSH directly from OpenWebUI with automatic safety checks for destructive commands.

## Quick Setup

### 1. Configure Your VMs
Copy the example config and edit it:
```bash
cp config.yaml.example config.yaml
nano config.yaml  # or use your preferred editor
```

Add your VMs:
```yaml
hosts:
  vm1:
    hostname: "192.168.1.100"
    username: "root"
    password: "yourpassword"
    description: "My Server"
```

### 2. Start the Server
```bash
docker compose up -d --build
```

### 3. Connect to OpenWebUI Network
```bash
# Find your OpenWebUI network name
docker network ls | grep openwebui

# Connect the container (replace 'openwebui_default' with your network name)
docker network connect openwebui_default ssh-control-mcp
```

### 4. Add Tool to OpenWebUI
1. Open OpenWebUI → **Workspace → Tools**
2. Click **+ Create Tool**
3. Copy and paste entire contents of `ssh_linux_control.py`
4. **Save**

Done! 🎉

## Usage Examples

Ask OpenWebUI:
- **"List my VMs"**
- **"Connect to vm1 and check disk space"**
- **"Show memory usage on vm1"**
- **"Run 'systemctl status nginx' on my server"**

## Features

✅ Password-based SSH authentication (no keys needed)  
✅ Automatic destructive command detection  
✅ Sudo support (uses password from config)  
✅ 40+ destructive command patterns detected  
✅ Real-time command output  

## Destructive Command Safety

Commands like `rm -rf`, `shutdown`, `systemctl stop`, etc. require explicit confirmation:
- First attempt: Shows warning
- Retry with `confirmed=True` to execute

## Troubleshooting

**Tool can't connect to server:**
```bash
# Check container is running
docker ps | grep ssh-control-mcp

# Check logs
docker logs ssh-control-mcp

# Test API
curl http://localhost:3000/api/hosts
```

**If OpenWebUI is containerized**, ensure both containers are on the same network:
```bash
docker network connect <openwebui-network> ssh-control-mcp
```

## File Structure
- `config.yaml.example` - Example configuration (safe to commit)
- `config.yaml` - Your VM credentials (gitignored, DO NOT COMMIT)
- `ssh_linux_control.py` - OpenWebUI tool file
- `docker-compose.yml` - Container configuration
- `src/ssh_control_mcp/` - MCP server & HTTP wrapper

## Security Notes
⚠️ **NEVER commit `config.yaml`** - it contains plain-text passwords  
⚠️ Use `config.yaml.example` as a template  
⚠️ Designed for local VM management on trusted networks only

## License
MIT License - See [LICENSE](LICENSE) file for details
