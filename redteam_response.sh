#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace
# redteam_response.sh — Detect red team activity and restore services
# Usage: sudo ./redteam_response.sh [users_file]
# Default users file: users.txt
# Run this when services go down or tampering is suspected.

set -uo pipefail

USERS_FILE="${1:-users.txt}"
BACKUP_BASE="/root/.cache"
SHARE_PATH="/srv/samba/compshare"
LOG_FILE="/root/redteam_response_$(date +%Y%m%d_%H%M%S).log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[CRIT]${NC}  $*" | tee -a "$LOG_FILE"; }
check() { echo -e "${CYAN}[CHECK]${NC} $*" | tee -a "$LOG_FILE"; }

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

echo "================================================================" | tee "$LOG_FILE"
echo " INCIDENT RESPONSE - $(date)"                                     | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"

ISSUES_FOUND=0

# ── 1. SERVICE STATUS ─────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== SERVICE STATUS ==="

for svc in sshd smbd nmbd fail2ban firewalld; do
    if systemctl is-active "$svc" &>/dev/null; then
        info "$svc is running."
    else
        error "$svc is DOWN. Attempting restart..."
        systemctl restart "$svc" 2>&1 | tee -a "$LOG_FILE" || \
            error "Failed to restart $svc — manual intervention required."
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

# ── 2. FIREWALL CHECK — USE sshd AND smbd INSTEAD OF ssh/samba ──────────────
echo "" | tee -a "$LOG_FILE"
check "=== FIREWALL RULES ==="

if ! firewall-cmd --list-services 2>/dev/null | grep -q "sshd"; then
    error "sshd not in firewall rules! Re-adding..."
    firewall-cmd --permanent --add-service=sshd
    firewall-cmd --reload
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    info "sshd firewall rule present."
fi

if ! firewall-cmd --list-services 2>/dev/null | grep -q "smbd"; then
    error "smbd not in firewall rules! Re-adding..."
    firewall-cmd --permanent --add-service=smbd
    firewall-cmd --reload
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    info "smbd firewall rule present."
fi

# ── 3. SSHD_CONFIG INTEGRITY ──────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== SSHD_CONFIG INTEGRITY ==="

LATEST_BACKUP=$(ls -1 "$BACKUP_BASE"/*/sshd_config 2>/dev/null | sort | tail -1)

if [[ -n "$LATEST_BACKUP" ]]; then
    if diff -q /etc/ssh/sshd_config "$LATEST_BACKUP" &>/dev/null; then
        info "sshd_config matches backup — no tampering detected."
    else
        error "sshd_config DIFFERS from backup!"
        diff /etc/ssh/sshd_config "$LATEST_BACKUP" | tee -a "$LOG_FILE"
        read -rp "  Restore sshd_config from backup? [y/N]: " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            chattr -i /etc/ssh/sshd_config 2>/dev/null || true
            cp "$LATEST_BACKUP" /etc/ssh/sshd_config
            sshd -t && systemctl restart sshd && info "sshd restored and restarted."
            chattr +i /etc/ssh/sshd_config
        fi
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    warn "No sshd_config backup found to compare against."
fi

# Dangerous settings check regardless of diff
if grep -qiE "^PermitRootLogin yes|^PasswordAuthentication yes.*#|^PubkeyAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    error "Dangerous setting detected in sshd_config!"
    grep -iE "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config | tee -a "$LOG_FILE"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# ── 4. SMB.CONF INTEGRITY ─────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== SMB.CONF INTEGRITY ==="

LATEST_SMB_BACKUP=$(ls -1 "$BACKUP_BASE"/*/smbd.conf 2>/dev/null | sort | tail -1)

if [[ -n "$LATEST_SMB_BACKUP" ]]; then
    if diff -q /etc/samba/smbd.conf "$LATEST_SMB_BACKUP" &>/dev/null; then
        info "smbd.conf matches backup — no tampering detected."
    else
        error "smb.conf DIFFERS from backup!"
        diff /etc/samba/smbd.conf "$LATEST_SMB_BACKUP" | tee -a "$LOG_FILE"
        read -rp "  Restore smbd.conf from backup? [y/N]: " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            chattr -i /etc/samba/smbd.conf 2>/dev/null || true
            cp "$LATEST_SMB_BACKUP" /etc/samba/smbd.conf
            testparm -s &>/dev/null && systemctl restart smbd nmbd && info "smbd.conf restored."
            chattr +i /etc/samba/smbd.conf
        fi
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    warn "No smbd.conf backup found to compare against."
fi

# ── 5. UNAUTHORIZED USER CHECK ────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== USER ACCOUNT CHECK ==="

if [[ -f "$USERS_FILE" ]]; then
    EXPECTED_USERS=()
    while IFS= read -r u || [[ -n "$u" ]]; do
        [[ -z "$u" || "$u" == \#* ]] && continue
        EXPECTED_USERS+=("$(echo "$u" | tr -d '[:space:]')")
    done < "$USERS_FILE"

    CURRENT_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
    while IFS= read -r cu; do
        if [[ ! " ${EXPECTED_USERS[*]} " =~ " $cu " ]]; then
            error "UNEXPECTED user found: $cu"
            last "$cu" 2>/dev/null | head -5 | tee -a "$LOG_FILE"
            warn "  Consider: userdel -r $cu"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    done <<< "$CURRENT_USERS"
    info "User check complete."
else
    warn "users.txt not found — skipping user account check."
fi

# ── 6. AUTHORIZED_KEYS AUDIT ──────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== AUTHORIZED_KEYS AUDIT ==="

BACKUP_KEYS_DIR=$(ls -1d "$BACKUP_BASE"/*/authorized_keys 2>/dev/null | sort | tail -1)

while IFS=: read -r username _ uid _ _ homedir _; do
    [[ $uid -lt 1000 ]] && continue
    KEYFILE="$homedir/.ssh/authorized_keys"
    [[ ! -f "$KEYFILE" ]] && continue

    KEY_COUNT=$(grep -c 'ssh-' "$KEYFILE" 2>/dev/null || echo 0)
    info "  $username: $KEY_COUNT key(s) in authorized_keys"

    if [[ -n "$BACKUP_KEYS_DIR" && -f "$BACKUP_KEYS_DIR/${username}_authorized_keys" ]]; then
        if ! diff -q "$KEYFILE" "$BACKUP_KEYS_DIR/${username}_authorized_keys" &>/dev/null; then
            error "authorized_keys for $username has CHANGED since backup!"
            diff "$KEYFILE" "$BACKUP_KEYS_DIR/${username}_authorized_keys" | tee -a "$LOG_FILE"
            read -rp "  Restore $username authorized_keys from backup? [y/N]: " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then
                cp "$BACKUP_KEYS_DIR/${username}_authorized_keys" "$KEYFILE"
                chmod 600 "$KEYFILE"
                info "Restored authorized_keys for $username."
            fi
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    fi
done < /etc/passwd

# ── 7. ACTIVE CONNECTIONS AUDIT ───────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== ACTIVE CONNECTIONS ==="

info "Currently logged-in users:"
w 2>/dev/null | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
info "Active SSH sessions:"
ss -tnp | grep ':22' | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
info "Active SMB sessions:"
smbstatus --brief 2>/dev/null | tee -a "$LOG_FILE" || true

# ── 8. RECENT AUTH LOG REVIEW ─────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== RECENT AUTH EVENTS (last 20) ==="
grep -E "sshd|smbd|pam" /var/log/secure 2>/dev/null | tail -20 | tee -a "$LOG_FILE"

# ── 9. CRON / PERSISTENCE CHECK ───────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== CRON PERSISTENCE CHECK ==="

SUSPICIOUS=0
for u in $(cut -d: -f1 /etc/passwd); do
    CRON_OUT=$(crontab -u "$u" -l 2>/dev/null)
    if [[ -n "$CRON_OUT" ]]; then
        warn "Crontab entries found for user: $u"
        echo "$CRON_OUT" | tee -a "$LOG_FILE"
        SUSPICIOUS=$((SUSPICIOUS + 1))
    fi
done

for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/*; do
    [[ -f "$f" ]] && check "  System cron: $f"
done

[[ $SUSPICIOUS -gt 0 ]] && ISSUES_FOUND=$((ISSUES_FOUND + 1))

# ── 10. SMB SHARE FILE INTEGRITY ─────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== SMB SHARE FILE CHECK ==="

if [[ -d "$SHARE_PATH" ]]; then
    info "Files in $SHARE_PATH:"
    ls -la "$SHARE_PATH" | tee -a "$LOG_FILE"
else
    error "Share path $SHARE_PATH not found!"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# ── SELINUX STATUS ────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
check "=== SELINUX STATUS ==="
SELINUX_STATUS=$(getenforce)
if [[ "$SELINUX_STATUS" != "Enforcing" ]]; then
    error "SELinux is NOT enforcing! Status: $SELINUX_STATUS"
    read -rp "  Re-enable SELinux enforcing now? [y/N]: " yn
    [[ "$yn" =~ ^[Yy]$ ]] && setenforce 1 && info "SELinux set to Enforcing."
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    info "SELinux is Enforcing."
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"
if [[ $ISSUES_FOUND -eq 0 ]]; then
    info "All checks passed. No issues detected."
else
    error "$ISSUES_FOUND issue(s) detected and flagged. Review log: $LOG_FILE"
fi
echo "================================================================" | tee -a "$LOG_FILE"
echo " Log saved to: $LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"