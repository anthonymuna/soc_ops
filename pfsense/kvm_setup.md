# Syndicate4 Firewall — NFT Blocker

**Approach:** Host-based nftables firewall via a lightweight FastAPI service.
Replaces pfSense/KVM. Responder container calls the blocker API to auto-block threat IPs.

---

## Architecture

```
ML Service → detects threat → Elasticsearch alert
Responder  → polls alerts   → POST /api/v1/firewall/alias/entry
NFT Blocker → runs on host  → nft add element → kernel drops packets
```

---

## Service Location

- **Host:** `<server-ip>`
- **Port:** `8080`
- **Systemd unit:** `nft-blocker`
- **Install path:** `/opt/nft-blocker/`

---

## Management

```bash
# SSH into server
ssh -i keys/syndicate4.pem ubuntu@<server-ip>

# Service status
sudo systemctl status nft-blocker

# View blocked IPs (kernel)
sudo nft list set inet filter syndicate4_blocklist

# View blocked IPs (API)
curl -s http://localhost:8080/api/v1/firewall/alias \
  -H "Authorization: $PFSENSE_API_KEY" | python3 -m json.tool

# Manual block
curl -s -X POST http://localhost:8080/api/v1/firewall/alias/entry \
  -H "Authorization: $PFSENSE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"syndicate4_blocklist","address":"1.2.3.4","detail":"manual"}'

# Manual unblock
curl -s -X DELETE http://localhost:8080/api/v1/firewall/alias/entry \
  -H "Authorization: $PFSENSE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"syndicate4_blocklist","address":"1.2.3.4","detail":""}'

# Restart service
sudo systemctl restart nft-blocker

# View logs
sudo journalctl -u nft-blocker -f
```

---

## Environment (.env)

```
PFSENSE_URL=http://host-gateway:8080
PFSENSE_API_KEY=<key from /etc/systemd/system/nft-blocker.service>
DRY_RUN=false
NEVER_BLOCK=10.104.4.0/24
```

---

## nftables Rules

```bash
# View full ruleset
sudo nft list ruleset

# Flush blocklist (emergency — unblocks all IPs)
sudo nft flush set inet filter syndicate4_blocklist
```

---

## Network Summary

| Component       | Address           | Role                        |
|-----------------|-------------------|-----------------------------|
| NFT Blocker API | `<server-ip>:8080`| Firewall management API     |
| Responder       | Docker container  | Polls alerts, calls API     |
| nftables set    | kernel            | Drops packets from blocked IPs |
