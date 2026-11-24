# Lab setup: Ubuntu VM in VirtualBox

The stack runs in an Ubuntu Server VM. You use Kibana from your normal Windows browser through a port forward, so the VM doesn't need a desktop.

## 1. Create the VM

1. Download **Ubuntu Server 24.04 LTS** (ISO) from ubuntu.com.
2. In VirtualBox, click **New** and use these settings:
   - Name: `mini-soc` · ISO: the Ubuntu ISO · check **Skip Unattended Installation**
   - **Memory: 8192 MB** (6144 is the minimum; Elasticsearch + Kibana use about 4 GB)
   - **CPUs: 4**
   - **Disk: 40 GB**
3. **Settings → Network → Adapter 1:** leave it on **NAT**.
4. **Settings → Network → Advanced → Port Forwarding** and add two rules:

   | Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
   |---|---|---|---|---|---|
   | ssh | TCP | 127.0.0.1 | 2222 | | 22 |
   | kibana | TCP | 127.0.0.1 | 5601 | | 5601 |

   Setting Host IP to `127.0.0.1` means only *your* PC can reach Kibana. Other devices on your Wi-Fi can't.

5. Start the VM and install Ubuntu with the defaults. On the SSH screen, check **Install OpenSSH server**.

## 2. Connect from Windows

Open Windows Terminal or PowerShell:

```powershell
ssh -p 2222 YOUR_VM_USERNAME@127.0.0.1
```

From here on you can copy and paste commands from Windows, which is easier than typing in the VirtualBox window.

## 3. Install Docker (inside the VM)

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl git

# Docker's official apt repository
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Run docker without sudo (log out and back in afterwards)
sudo usermod -aG docker $USER
```

Log out (`exit`), SSH back in, and check it works: `docker run --rm hello-world`

## 4. Kernel setting Elasticsearch needs

```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
```

## 5. Start the stack

```bash
git clone https://github.com/auxilio3/mini-soc-dashboard.git
cd mini-soc-dashboard
docker compose up -d
docker compose ps          # wait until elasticsearch shows "healthy" (1-2 min)
python3 -m soc.setup_stack
```

Open **http://localhost:5601** in your Windows browser. Kibana is up.

## Troubleshooting

| Problem | Fix |
|---|---|
| VirtualBox says VT-x/AMD-V is unavailable, or the VM is very slow | Enable virtualization in your BIOS. On Windows, turning off "Memory integrity" (Core Isolation) or Hyper-V can help VirtualBox run at full speed. |
| Elasticsearch keeps restarting and `docker compose logs elasticsearch` says `max virtual memory areas vm.max_map_count [65530] is too low` | Redo step 4. |
| Container exits with code 137 | Out of memory. Give the VM more RAM, or set `ES_HEAP=512m` in `.env`. |
| Kibana says "Kibana server is not ready yet" | Normal for the first 1-2 minutes. |
| `localhost:5601` doesn't load in Windows | Check the port-forward rule, and that `docker compose ps` shows Kibana running. |

To stop everything: `docker compose down`. Add `-v` to also delete the stored data and start fresh.
