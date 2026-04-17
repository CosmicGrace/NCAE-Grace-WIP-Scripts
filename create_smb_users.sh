#!/bin/bash
# create_smb_users.sh — Create Linux users and Samba accounts
# Handles: useradd (no-login), smbpasswd, smbgroup membership
# Does NOT touch smb.conf — run setup_smb.sh for that
# Usage: sudo ./create_smb_users.sh [users_file]
# Default users file: users.txt

set -uo pipefail

USERS_FILE="${1:-users.txt}"
SMB_GROUP="smbgroup"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }
[[ ! -f "$USERS_FILE" ]] && { error "Users file '$USERS_FILE' not found."; exit 1; }

# Verify smbpasswd is available (samba must be installed first)
if ! command -v smbpasswd &>/dev/null; then
    error "smbpasswd not found. Run setup_smb.sh first."
    exit 1
fi

# Ensure the SMB group exists
groupadd "$SMB_GROUP" 2>/dev/null || info "Group '$SMB_GROUP' already exists."

# Prompt once for the password to use for all users
read -s -p "Enter SMB password for all users in $USERS_FILE: " SMB_PASS
echo ""
[[ -z "$SMB_PASS" ]] && { error "Password cannot be empty."; exit 1; }

CREATED=0
EXISTING=0

while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"

    # ── CREATE LINUX USER (no shell — SMB only) ───────────────────────────────
    if ! id "$user" &>/dev/null; then
        useradd -M -s /sbin/nologin "$user"
        info "Created Linux user (no-login): $user"
        CREATED=$((CREATED + 1))
    else
        info "Linux user already exists: $user"
        EXISTING=$((EXISTING + 1))
    fi

    # ── ADD TO SMB GROUP ──────────────────────────────────────────────────────
    usermod -aG "$SMB_GROUP" "$user"
    info "  Added $user to group $SMB_GROUP"

    # ── CREATE/UPDATE SAMBA ACCOUNT ───────────────────────────────────────────
    printf "%s\n%s\n" "$SMB_PASS" "$SMB_PASS" | smbpasswd -a -s "$user" &>/dev/null
    smbpasswd -e "$user" &>/dev/null
    info "  Samba account configured: $user"

done < "$USERS_FILE"

echo ""
info "Samba user setup complete. Created: $CREATED  Already existed: $EXISTING"
echo ""
info "Current Samba user database:"
pdbedit -L
