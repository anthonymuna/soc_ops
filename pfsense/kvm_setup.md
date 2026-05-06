# pfSense VM on KVM — Syndicate4 Setup

**Goal:** pfSense VM on the Syndicate4 host. NOT a gateway yet — Phase 1 only.
Responder container calls pfSense API to auto-block detected threat IPs.

---

## 1. Prerequisites

SSH into the Syndicate4 server:

```bash
ssh -i keys/syndicate4.pem ubuntu@10.104.4.68
```

Confirm CPU supports virtualisation:

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # must be > 0
kvm-ok                                # must say "KVM acceleration can be used"
```

---

## 2. Install KVM Stack

```bash
sudo apt update
sudo apt install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  bridge-utils \
  virtinst \
  virt-manager \
  cpu-checker

sudo usermod -aG libvirt,kvm ubuntu
newgrp libvirt

sudo systemctl enable --now libvirtd
virsh list --all   # should return empty list, no errors
```

---

## 3. Create Internal LAN Bridge

pfSense LAN will live on `192.168.100.0/24`. This bridge is isolated — no routing
change to the host, no lockout risk.

```bash
sudo virsh net-define /dev/stdin <<'EOF'
<network>
  <name>syndicate-lan</name>
  <bridge name="virbr-syn" stp="on" delay="0"/>
  <ip address="192.168.100.254" netmask="255.255.255.0"/>
</network>
EOF

sudo virsh net-start syndicate-lan
sudo virsh net-autostart syndicate-lan
virsh net-list --all   # syndicate-lan should show active
```

pfSense LAN IP will be `192.168.100.1`. Host can reach it at `192.168.100.254`.

---

## 4. Download pfSense ISO

Download pfSense CE from **https://www.pfsense.org/download/**

Select:
- Architecture: `AMD64 (64-bit)`
- Installer: `DVD Image (ISO) Installer`
- Mirror: closest to your region

Copy to server:

```bash
scp -i keys/syndicate4.pem \
  ~/Downloads/pfSense-CE-*.iso \
  ubuntu@10.104.4.68:/var/lib/libvirt/images/pfsense.iso
```

---

## 5. Create pfSense VM

```bash
sudo virt-install \
  --name pfsense \
  --ram 2048 \
  --vcpus 2 \
  --os-variant freebsd13.0 \
  --disk path=/var/lib/libvirt/images/pfsense-disk.qcow2,size=16,format=qcow2 \
  --cdrom /var/lib/libvirt/images/pfsense.iso \
  --network network=default,model=virtio \
  --network network=syndicate-lan,model=virtio \
  --graphics vnc,listen=127.0.0.1,port=5900 \
  --noautoconsole \
  --boot cdrom,hd
```

`default` network = WAN (NAT, internet access for pfSense updates).
`syndicate-lan` = LAN (where responder container will reach pfSense API).

---

## 6. Connect to VM Console (VNC)

From your local machine, SSH tunnel VNC:

```bash
ssh -i keys/syndicate4.pem -L 5900:127.0.0.1:5900 ubuntu@10.104.4.68
```

Then open any VNC client → `localhost:5900`.

Install pfSense through the graphical installer. Accept defaults.
When asked about VLAN: **No**.
WAN interface: `vtnet0`. LAN interface: `vtnet1`.

---

## 7. Post-Install pfSense Config

After reboot, pfSense console menu shows. Set LAN IP:

```
Option 2 — Set interface(s) IP address
  → Interface: LAN (vtnet1)
  → IP: 192.168.100.1
  → Subnet: 24
  → Gateway: leave blank
  → IPv6: No
  → DHCP: No
```

Access WebGUI from the Syndicate4 host:

```bash
curl -k https://192.168.100.1   # should return pfSense login page HTML
```

Default credentials: `admin` / `pfsense` — **change on first login**.

---

## 8. Install pfSense API Package

In pfSense WebGUI (`https://192.168.100.1`):

```
System → Package Manager → Available Packages
  → Search: "API"
  → Install: pfSense-pkg-API
  → Confirm install
```

After install:

```
System → API → Settings
  → Enable: checked
  → Auth Mode: API Key
  → Save
```

Generate API key:

```
System → API → Keys → Generate Key
  → Copy the key — paste into docker-compose PFSENSE_API_KEY env var
```

---

## 9. Create Blocklist Alias

```
Firewall → Aliases → Add
  Name:        syndicate4_blocklist
  Description: Auto-blocked by Syndicate4 ML
  Type:        Host(s)
  → Save → Apply Changes
```

---

## 10. Create Block Firewall Rule

```
Firewall → Rules → WAN → Add (top of list)
  Action:      Block
  Interface:   WAN
  Source:      Single host or alias → syndicate4_blocklist
  Destination: any
  Description: Syndicate4 auto-block
  → Save → Apply Changes
```

---

## 11. Verify API Works

From the Syndicate4 host (not inside Docker — bridge is on host network):

```bash
# List aliases
curl -sk -H "Authorization: YOUR_API_KEY" \
  https://192.168.100.1/api/v1/firewall/alias | python3 -m json.tool

# Add a test IP
curl -sk -X POST \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"syndicate4_blocklist","address":"1.2.3.4","detail":"test"}' \
  https://192.168.100.1/api/v1/firewall/alias/entry

# Confirm it appeared in pfSense WebGUI:
# Firewall → Aliases → syndicate4_blocklist → should list 1.2.3.4

# Clean up test IP
curl -sk -X DELETE \
  -H "Authorization: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"syndicate4_blocklist","address":"1.2.3.4"}' \
  https://192.168.100.1/api/v1/firewall/alias/entry
```

---

## 12. Expose Bridge to Docker

The responder container needs to reach `192.168.100.1`. Add the bridge IP to
docker-compose so containers can route to it:

```bash
# On server — add route so Docker containers reach the syndicate-lan bridge
sudo ip route add 192.168.100.0/24 dev virbr-syn
```

Make it persistent across reboots:

```bash
sudo tee /etc/networkd-dispatcher/routable.d/syndicate-lan-route <<'EOF'
#!/bin/bash
ip route add 192.168.100.0/24 dev virbr-syn 2>/dev/null || true
EOF
sudo chmod +x /etc/networkd-dispatcher/routable.d/syndicate-lan-route
```

---

## VM Management

```bash
# Status
virsh list --all

# Start / stop
virsh start pfsense
virsh shutdown pfsense

# Force off (last resort)
virsh destroy pfsense

# VNC port
virsh vncdisplay pfsense

# Delete VM entirely (irreversible)
virsh destroy pfsense
virsh undefine pfsense --remove-all-storage
```

---

## Network Summary

| Component | IP | Role |
|---|---|---|
| pfSense WAN | DHCP via `default` (NAT) | internet / updates |
| pfSense LAN | `192.168.100.1` | API endpoint |
| KVM bridge | `192.168.100.254` | host side of LAN bridge |
| Responder container | via host bridge route | calls pfSense API |
| Syndicate4 host | `10.104.4.68` | existing IP, unchanged |
