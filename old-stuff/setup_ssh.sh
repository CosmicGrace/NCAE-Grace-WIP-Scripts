#!/bin/bash
# setup_ssh.sh — SSH service configuration and hardening
# Handles: sshd_config, fail2ban, firewall
# Does NOT create users — run create_ssh_users.sh first
# Usage: sudo ./setup_ssh.sh [users_file]
# Default users file: users.txt (read only for AllowUsers directive)

set -uo pipefail

USERS_FILE="${1:-users.txt}"
BACKUP_DIR="/root/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }
[[ ! -f "$USERS_FILE" ]] && { error "Users file '$USERS_FILE' not found."; exit 1; }

mkdir -p "$BACKUP_DIR"

# ── DEPENDENCIES ─────────────────────────────────────────────────────────────
info "Checking dependencies..."

if ! rpm -q openssh-server &>/dev/null; then
    info "Installing openssh-server..."
    dnf install -y openssh-server
fi

if ! rpm -q epel-release &>/dev/null; then
    info "Installing EPEL repository..."
    dnf install -y epel-release
fi

if ! rpm -q fail2ban &>/dev/null; then
    info "Installing fail2ban..."
    dnf install -y fail2ban
fi

# ── BACKUP ───────────────────────────────────────────────────────────────────
info "Backing up existing sshd_config..."
[[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$TIMESTAMP"

# ── BUILD AllowUsers FROM users.txt ──────────────────────────────────────────
info "Reading AllowUsers list from $USERS_FILE..."
ALLOW_USERS=""
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"
    ALLOW_USERS="$ALLOW_USERS $user"
done < "$USERS_FILE"

[[ -z "$ALLOW_USERS" ]] && { error "No users found in $USERS_FILE."; exit 1; }
info "AllowUsers will be set to:$ALLOW_USERS"

# ── SSHD_CONFIG ───────────────────────────────────────────────────────────────
info "Writing hardened sshd_config..."
chattr -i /etc/ssh/sshd_config 2>/dev/null || true

cat > /etc/ssh/sshd_config << 'EOF'
Port 22
AddressFamily inet

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no

MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no

LogLevel VERBOSE
SyslogFacility AUTHPRIV

KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF

echo "AllowUsers$ALLOW_USERS" >> /etc/ssh/sshd_config

# ── VALIDATE CONFIG ───────────────────────────────────────────────────────────
info "Testing sshd_config..."
if ! sshd -t; then
    error "sshd config test FAILED. Restoring backup."
    cp "$BACKUP_DIR/sshd_config.$TIMESTAMP" /etc/ssh/sshd_config
    exit 1
fi

# ── FAIL2BAN ──────────────────────────────────────────────────────────────────
info "Configuring fail2ban for SSH..."
[[ ! -f /etc/fail2ban/jail.local ]] && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd-competition.conf << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/secure
maxretry = 3
bantime  = 3600
findtime = 600
EOF

# ── FIREWALL ──────────────────────────────────────────────────────────────────
info "Configuring firewall for SSH..."
systemctl is-active firewalld &>/dev/null || systemctl start firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
firewall-cmd --reload

# ── START / RESTART SERVICES ──────────────────────────────────────────────────
info "Enabling and starting services..."
systemctl enable --now sshd
systemctl restart sshd
systemctl enable --now fail2ban
systemctl restart fail2ban

# ── LOCK CONFIG ───────────────────────────────────────────────────────────────
info "Locking sshd_config with chattr +i..."
chattr +i /etc/ssh/sshd_config

echo ""
info "SSH service setup complete."
info "Backup saved: $BACKUP_DIR/sshd_config.$TIMESTAMP"
warn "Run create_ssh_users.sh to configure user accounts and authorized_keys."
warn "To edit sshd_config later: chattr -i /etc/ssh/sshd_config"
echo ""
systemctl status sshd --no-pager -l
