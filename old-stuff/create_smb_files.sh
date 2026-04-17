#!/bin/bash
# create_smb_files.sh — Pre-populate the SMB share with required files
# Handles: file creation, ownership, permissions, SELinux restore
# Does NOT touch smb.conf or user accounts
# Usage: sudo ./create_smb_files.sh [files_list]
# Default files list: smb_files.txt
#
# smb_files.txt format:
#   filename|exact file content
#   Lines starting with # are ignored

set -uo pipefail

FILES_LIST="${1:-smb_files.txt}"
SHARE_PATH="/srv/samba/compshare"
SMB_GROUP="smbgroup"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }
[[ ! -f "$FILES_LIST" ]] && { error "Files list '$FILES_LIST' not found."; exit 1; }
[[ ! -d "$SHARE_PATH" ]] && { error "Share path '$SHARE_PATH' not found. Run setup_smb.sh first."; exit 1; }

CREATED=0

while IFS='|' read -r filename content || [[ -n "$filename" ]]; do
    [[ -z "$filename" || "$filename" == \#* ]] && continue
    filename="$(echo "$filename" | tr -d '[:space:]')"

    # Write file — printf preserves content exactly, no trailing newline issues
    printf "%s\n" "$content" > "$SHARE_PATH/$filename"
    chown root:"$SMB_GROUP" "$SHARE_PATH/$filename"
    chmod 0664 "$SHARE_PATH/$filename"

    info "Created: $SHARE_PATH/$filename"
    CREATED=$((CREATED + 1))

done < "$FILES_LIST"

# Re-apply SELinux context after creating new files
info "Restoring SELinux contexts on share directory..."
restorecon -Rv "$SHARE_PATH"

echo ""
info "$CREATED file(s) created in $SHARE_PATH"
echo ""
info "Current share contents:"
ls -la "$SHARE_PATH"
echo ""
info "SELinux contexts:"
ls -Z "$SHARE_PATH"
