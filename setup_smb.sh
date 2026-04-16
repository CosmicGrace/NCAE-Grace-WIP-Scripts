#!/bin/bash
# setup_smb.sh — Samba setup, user configuration, share creation, and hardening
# Usage: sudo ./setup_smb.sh [users_file] [files_list]
# Defaults: users.txt, smb_files.txt

set -uo pipefail

USERS_FILE="${1:-users.txt}"
FILES_LIST="${2:-smb_files.txt}"
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
[[ ! -f "$FILES_LIST" ]] && { warn "Files list '$FILES_LIST' not found. Skipping file pre-population."; FILES_LIST=""; }

mkdir -p "$BACKUP_DIR"

# ── DEPENDENCY CHECK ──────────────────────────────────────────────────────────
info "Checking and installing dependencies..."

for pkg in samba samba-client samba-common policycoreutils-python-utils; do
    if ! rpm -q "$pkg" &>/dev/null; then
        info "Installing $pkg..."
        dnf install -y "$pkg"
    else
        info "$pkg already installed."
    fi
done

# ── BACKUP ────────────────────────────────────────────────────────────────────
info "Backing up existing smb.conf..."
[[ -f /etc/samba/smb.conf ]] && cp /etc/samba/smb.conf "$BACKUP_DIR/smb.conf.$TIMESTAMP"

# ── GROUP AND DIRECTORY ───────────────────────────────────────────────────────
info "Creating SMB group and share directory..."
groupadd "$SMB_GROUP" 2>/dev/null || info "Group '$SMB_GROUP' already exists."
mkdir -p "$SHARE_PATH"

# ── USER SETUP ────────────────────────────────────────────────────────────────
info "Setting SMB password (used for all users in this run)..."
read -s -p "  Enter default SMB password for all users: " SMB_PASS
echo ""
[[ -z "$SMB_PASS" ]] && { error "Password cannot be empty."; exit 1; }

VALID_USERS=""
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"

    if ! id "$user" &>/dev/null; then
        useradd -M -s /sbin/nologin "$user"
        info "Created Linux user (no-login): $user"
    else
        info "Linux user already exists: $user"
    fi

    usermod -aG "$SMB_GROUP" "$user"

    printf "%s\n%s\n" "$SMB_PASS" "$SMB_PASS" | smbpasswd -a -s "$user" &>/dev/null
    smbpasswd -e "$user" &>/dev/null
    info "Samba account configured: $user"

    VALID_USERS="$VALID_USERS $user"
done < "$USERS_FILE"

VALID_USERS_TRIMMED="$(echo "$VALID_USERS" | sed 's/^ //')"

# ── SMB.CONF ──────────────────────────────────────────────────────────────────
info "Writing smb.conf..."
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

info "Testing smb.conf..."
if ! testparm -s /etc/samba/smb.conf &>/dev/null; then
    error "smb.conf test FAILED. Check: testparm"
    exit 1
fi

# ── FILESYSTEM PERMISSIONS ────────────────────────────────────────────────────
info "Setting filesystem permissions on share..."
chown -R root:"$SMB_GROUP" "$SHARE_PATH"
chmod -R 0770 "$SHARE_PATH"

# ── PRE-POPULATE FILES ────────────────────────────────────────────────────────
if [[ -n "$FILES_LIST" ]]; then
    info "Pre-populating share files from $FILES_LIST..."
    while IFS='|' read -r filename content || [[ -n "$filename" ]]; do
        [[ -z "$filename" || "$filename" == \#* ]] && continue
        filename="$(echo "$filename" | tr -d '[:space:]')"
        printf "%s\n" "$content" > "$SHARE_PATH/$filename"
        chown root:"$SMB_GROUP" "$SHARE_PATH/$filename"
        chmod 0664 "$SHARE_PATH/$filename"
        info "Created: $SHARE_PATH/$filename"
    done < "$FILES_LIST"
fi

# ── SELINUX ───────────────────────────────────────────────────────────────────
info "Applying SELinux contexts..."
semanage fcontext -a -t samba_share_t "$SHARE_PATH(/.*)?" 2>/dev/null || \
    semanage fcontext -m -t samba_share_t "$SHARE_PATH(/.*)?"
restorecon -Rv "$SHARE_PATH"
setsebool -P samba_export_all_rw on

# ── FIREWALL ──────────────────────────────────────────────────────────────────
info "Configuring firewall..."
systemctl is-active firewalld &>/dev/null || systemctl start firewalld
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload

# ── START SERVICES ────────────────────────────────────────────────────────────
info "Enabling and starting Samba services..."
systemctl enable --now smbd nmbd
systemctl restart smbd nmbd

# ── LOCK CONFIG ───────────────────────────────────────────────────────────────
info "Locking smb.conf with chattr..."
chattr +i /etc/samba/smb.conf

# ── VERIFICATION ─────────────────────────────────────────────────────────────
echo ""
info "Verifying Samba users..."
pdbedit -L

echo ""
info "Testing local SMB connection..."
smbclient -L localhost -U "$(echo "$VALID_USERS" | awk '{print $1}')" --password="$SMB_PASS" 2>&1 | head -20

echo ""
info "SMB setup complete. Backup at: $BACKUP_DIR/smb.conf.$TIMESTAMP"
warn "To edit smb.conf later: chattr -i /etc/samba/smb.conf"
warn "To change an SMB user password: smbpasswd USERNAME"
