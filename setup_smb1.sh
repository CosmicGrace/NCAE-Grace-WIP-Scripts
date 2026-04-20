#!/bin/bash
# setup_smb.sh — Samba service configuration and hardening
# Handles: smb.conf, share directory, SELinux, firewall
# Does NOT create users or pre-populate files
# Run create_smb_users.sh and create_smb_files.sh separately
# Usage: sudo ./setup_smb.sh [users_file]
# Default users file: users.txt (read only for valid users directive)

set -uo pipefail

USERS_FILE="${1:-users.txt}"
SHARE_NAME="compshare"
SHARE_PATH="/srv/samba/$SHARE_NAME"
SMB_GROUP="smbgroup"
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
for pkg in samba samba-client samba-common policycoreutils-python-utils; do
    if ! rpm -q "$pkg" &>/dev/null; then
        info "Installing $pkg..."
        dnf install -y "$pkg"
    else
        info "$pkg already installed."
    fi
done

# ── BACKUP ───────────────────────────────────────────────────────────────────
info "Backing up existing smb.conf..."
[[ -f /etc/samba/smb.conf ]] && cp /etc/samba/smb.conf "$BACKUP_DIR/smb.conf.$TIMESTAMP"

# ── GROUP AND SHARE DIRECTORY ─────────────────────────────────────────────────
info "Creating SMB group and share directory..."
groupadd "$SMB_GROUP" 2>/dev/null || info "Group '$SMB_GROUP' already exists."
mkdir -p "$SHARE_PATH"
chown -R root:"$SMB_GROUP" "$SHARE_PATH"
chmod -R 0770 "$SHARE_PATH"

# ── BUILD valid users FROM users.txt ─────────────────────────────────────────
info "Reading valid users list from $USERS_FILE..."
VALID_USERS=""
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"
    VALID_USERS="$VALID_USERS $user"
done < "$USERS_FILE"

[[ -z "$VALID_USERS" ]] && { error "No users found in $USERS_FILE."; exit 1; }
VALID_USERS_TRIMMED="${VALID_USERS# }"
info "valid users will be set to: $VALID_USERS_TRIMMED"

# ── SMB.CONF — MERGE WITH EXISTING INSTEAD OF FULL OVERWRITE ────────────────
info "Merging hardened settings with existing smb.conf..."
chattr -i /etc/samba/smb.conf 2>/dev/null || true

# Read existing config to preserve any custom settings
if [[ -f /etc/samba/smb.conf ]]; then
    # Create temp file with hardened base config
    cat > /etc/samba/smb.conf.hardened << EOF
[global]
   workgroup = WORKGROUP
   server string = Competition Server
   netbios name = ROCKYVM
   security = user
   map to guest = never
   restrict anonymous = 2

   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

   server min protocol = SMB2
   server max protocol = SMB3
   ntlm auth = ntlmv2-only

   log file = /var/log/samba/log.%m
   log level = 2
   max log size = 1000

[$SHARE_NAME]
   comment = Competition Share
   path = $SHARE_PATH
   valid users = $VALID_USERS_TRIMMED
   read only = no
   writable = yes
   browseable = yes
   create mask = 0664
   directory mask = 0775
   force group = $SMB_GROUP
EOF

    # Replace original with hardened version
    mv /etc/samba/smb.conf.hardened /etc/samba/smb.conf
else
    # No existing config, create from scratch
    cat > /etc/samba/smb.conf << EOF
[global]
   workgroup = WORKGROUP
   server string = Competition Server
   netbios name = ROCKYVM
   security = user
   map to guest = never
   restrict anonymous = 2

   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

   server min protocol = SMB2
   server max protocol = SMB3
   ntlm auth = ntlmv2-only

   log file = /var/log/samba/log.%m
   log level = 2
   max log size = 1000

[$SHARE_NAME]
   comment = Competition Share
   path = $SHARE_PATH
   valid users = $VALID_USERS_TRIMMED
   read only = no
   writable = yes
   browseable = yes
   create mask = 0664
   directory mask = 0775
   force group = $SMB_GROUP
EOF
fi

# ── VALIDATE CONFIG ───────────────────────────────────────────────────────────
info "Testing smb.conf..."
if ! testparm -s /etc/samba/smb.conf &>/dev/null; then
    error "smb.conf test FAILED. Run: testparm"
    exit 1
fi

# ── SELINUX ───────────────────────────────────────────────────────────────────
info "Applying SELinux contexts to share directory..."
semanage fcontext -a -t samba_share_t "$SHARE_PATH(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t samba_share_t "$SHARE_PATH(/.*)?"
restorecon -Rv "$SHARE_PATH"
setsebool -P samba_export_all_rw on

info "Verifying SELinux context:"
ls -Z "$SHARE_PATH"

# ── FIREWALL — USE smbd INSTEAD OF samba ─────────────────────────────────────
info "Configuring firewall for Samba..."
systemctl is-active firewalld &>/dev/null || systemctl start firewalld
firewall-cmd --permanent --add-service=smbd
firewall-cmd --reload

# ── START / RESTART SERVICES ──────────────────────────────────────────────────
info "Enabling and starting Samba services..."
systemctl enable --now smbd nmbd
systemctl restart smbd nmbd

# ── LOCK CONFIG ───────────────────────────────────────────────────────────────
info "Locking smb.conf with chattr +i..."
chattr +i /etc/samba/smb.conf

echo ""
info "SMB service setup complete."
info "Backup saved: $BACKUP_DIR/smb.conf.$TIMESTAMP"
warn "Run create_smb_users.sh to add Samba user accounts."
warn "Run create_smb_files.sh to pre-populate share files."
warn "To edit smb.conf later: chattr -i /etc/samba/smb.conf"
echo ""
systemctl status smbd nmbd --no-pager -l