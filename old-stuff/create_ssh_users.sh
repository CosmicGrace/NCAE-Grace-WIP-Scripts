#!/bin/bash
# create_ssh_users.sh — Create Linux users and set up SSH directories
# Handles: useradd, .ssh/ directory creation, authorized_keys stubs
# Does NOT touch sshd_config — run setup_ssh.sh for that
# Usage: sudo ./create_ssh_users.sh [users_file]
# Default users file: users.txt

set -uo pipefail

USERS_FILE="${1:-users.txt}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }
[[ ! -f "$USERS_FILE" ]] && { error "Users file '$USERS_FILE' not found."; exit 1; }

CREATED=0
EXISTING=0

while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"

    # ── CREATE LINUX USER ─────────────────────────────────────────────────────
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash "$user"
        passwd "$user"
        info "Created user: $user"
        CREATED=$((CREATED + 1))
    else
        info "User already exists: $user"
        EXISTING=$((EXISTING + 1))
    fi

    # ── SET UP .ssh DIRECTORY ─────────────────────────────────────────────────
    HOMEDIR="$(getent passwd "$user" | cut -d: -f6)"
    mkdir -p "$HOMEDIR/.ssh"
    touch "$HOMEDIR/.ssh/authorized_keys"

    # Permissions must be exact — sshd rejects keys if these are wrong
    chmod 700 "$HOMEDIR/.ssh"
    chmod 600 "$HOMEDIR/.ssh/authorized_keys"
    chown -R "$user:$user" "$HOMEDIR/.ssh"

    info "  .ssh/ configured for $user ($HOMEDIR/.ssh)"

done < "$USERS_FILE"

echo ""
info "User setup complete. Created: $CREATED  Already existed: $EXISTING"
warn "Authorized keys files are empty stubs — add public keys manually:"
warn "  vim /home/USERNAME/.ssh/authorized_keys"
warn "  or: echo 'ssh-ed25519 AAAA...' >> /home/USERNAME/.ssh/authorized_keys"
echo ""

info "Current .ssh status for all processed users:"
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue
    user="$(echo "$user" | tr -d '[:space:]')"
    HOMEDIR="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
    [[ -z "$HOMEDIR" ]] && continue
    KEY_COUNT=$(grep -c 'ssh-' "$HOMEDIR/.ssh/authorized_keys" 2>/dev/null || echo 0)
    PERMS=$(stat -c "%a" "$HOMEDIR/.ssh" 2>/dev/null || echo "??")
    echo "  $user → $HOMEDIR/.ssh/ ($PERMS) | authorized_keys: $KEY_COUNT key(s)"
done < "$USERS_FILE"
