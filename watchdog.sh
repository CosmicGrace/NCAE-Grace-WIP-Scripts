#!/bin/bash
# =============================================================================
# watchdog.sh — Blue Team Persistence and Service Guardian
# =============================================================================
# PURPOSE : Runs via cron every minute. Detects and automatically recovers
#           from red team attacks: downed services, config tampering, missing
#           files, locked-out users, and firewall changes.
#
# HOW TO HIDE IT (competition strategy):
#   1. Store this script somewhere non-obvious:
#      cp watchdog.sh /usr/local/lib/.sysupdate        (hidden with dot prefix)
#      chmod 700 /usr/local/lib/.sysupdate             (only root can read/run)
#      chattr +i /usr/local/lib/.sysupdate             (immutable — can't be deleted)
#
#   2. Install the cron job under root:
#      crontab -e   (as root)
#      Add: * * * * * /usr/local/lib/.sysupdate >> /var/log/.watchdog.log 2>&1
#
#   3. Also hide the log:
#      touch /var/log/.watchdog.log
#      chattr +a /var/log/.watchdog.log  (+a = append only, can't be cleared)
#
# WHY CRON, NOT A SYSTEMD SERVICE:
#   Red team commonly kills/disables systemd services. Cron jobs are less
#   obvious targets and persist even if the red team disables custom services.
#   Running under root's crontab means it survives user-level attacks.
#
# USAGE  : Normally runs via cron. Manual test: sudo ./watchdog.sh
# =============================================================================

BACKUP_DIR="/root/backups"                  # Where your config backups live
SHARE_PATH="/srv/samba/compshare"           # SMB share directory
SHARE_FILES_LIST="/root/smb_files.txt"      # smb_files.txt for restoring content
LOG_PREFIX="[WATCHDOG $(date '+%Y-%m-%d %H:%M:%S')]"

# Auto-detect service names (same logic as setup scripts)
SSH_SERVICE="sshd"; systemctl list-unit-files ssh.service &>/dev/null && SSH_SERVICE="ssh"
SMB_SERVICE="smbd"; systemctl list-unit-files smb.service &>/dev/null && SMB_SERVICE="smb"
NMB_SERVICE="nmbd"; systemctl list-unit-files nmb.service &>/dev/null && NMB_SERVICE="nmb"

# =============================================================================
# HELPER: find the most recent backup of a given filename
# =============================================================================
latest_backup() {
    local filename="$1"
    ls -1t "$BACKUP_DIR"/*/"$filename" 2>/dev/null | head -1
}

# =============================================================================
# 1. SERVICE WATCHDOG — restart downed services
# =============================================================================
for svc in "$SSH_SERVICE" "$SMB_SERVICE" "$NMB_SERVICE" fail2ban firewalld; do
    if ! systemctl is-active "$svc" &>/dev/null; then
        echo "$LOG_PREFIX ALERT: $svc is DOWN — attempting restart"
        systemctl restart "$svc" 2>&1
        if systemctl is-active "$svc" &>/dev/null; then
            echo "$LOG_PREFIX RECOVERED: $svc is back online"
        else
            echo "$LOG_PREFIX FAILED: Could not restart $svc — manual intervention needed"
        fi
    fi
done

# =============================================================================
# 2. FIREWALL WATCHDOG — re-add rules if removed
# =============================================================================
if systemctl is-active firewalld &>/dev/null; then
    # Check SSH firewall rule
    if ! firewall-cmd --list-services 2>/dev/null | grep -qw "ssh"; then
        echo "$LOG_PREFIX ALERT: SSH firewall rule missing — restoring"
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
    fi
    # Check Samba firewall rule
    if ! firewall-cmd --list-services 2>/dev/null | grep -qw "samba"; then
        echo "$LOG_PREFIX ALERT: Samba firewall rule missing — restoring"
        firewall-cmd --permanent --add-service=samba
        firewall-cmd --reload
    fi
fi

# =============================================================================
# 3. SSH CONFIG GUARDIAN — detect and restore tampered sshd_config
# =============================================================================
LATEST_SSH_BACKUP="$(latest_backup sshd_config)"

if [[ -n "$LATEST_SSH_BACKUP" && -f /etc/ssh/sshd_config ]]; then
    if ! diff -q /etc/ssh/sshd_config "$LATEST_SSH_BACKUP" &>/dev/null; then
        echo "$LOG_PREFIX ALERT: sshd_config TAMPERED — restoring from $LATEST_SSH_BACKUP"
        chattr -i /etc/ssh/sshd_config 2>/dev/null || true
        cp "$LATEST_SSH_BACKUP" /etc/ssh/sshd_config
        if sshd -t; then
            systemctl restart "$SSH_SERVICE"
            chattr +i /etc/ssh/sshd_config
            echo "$LOG_PREFIX RECOVERED: sshd_config restored and service restarted"
        else
            echo "$LOG_PREFIX ERROR: Restored config failed sshd -t check"
        fi
    fi
fi

# =============================================================================
# 4. SMB CONFIG GUARDIAN — detect and restore tampered smb.conf
# =============================================================================
LATEST_SMB_BACKUP="$(latest_backup smb.conf)"

if [[ -n "$LATEST_SMB_BACKUP" && -f /etc/samba/smb.conf ]]; then
    if ! diff -q /etc/samba/smb.conf "$LATEST_SMB_BACKUP" &>/dev/null; then
        echo "$LOG_PREFIX ALERT: smb.conf TAMPERED — restoring from $LATEST_SMB_BACKUP"
        chattr -i /etc/samba/smb.conf 2>/dev/null || true
        cp "$LATEST_SMB_BACKUP" /etc/samba/smb.conf
        if testparm -s &>/dev/null; then
            systemctl restart "$SMB_SERVICE" "$NMB_SERVICE"
            chattr +i /etc/samba/smb.conf
            echo "$LOG_PREFIX RECOVERED: smb.conf restored and services restarted"
        else
            echo "$LOG_PREFIX ERROR: Restored smb.conf failed testparm check"
        fi
    fi
fi

# =============================================================================
# 5. SMB SHARE FILE GUARDIAN — restore required files if deleted/modified
# =============================================================================
# The competition SMB Read task checks specific files with exact content.
# If red team deletes or modifies them, you lose points instantly.
if [[ -f "$SHARE_FILES_LIST" && -d "$SHARE_PATH" ]]; then
    while IFS='|' read -r filename expected_content || [[ -n "$filename" ]]; do
        [[ -z "$filename" || "$filename" == \#* ]] && continue
        filename="$(echo "$filename" | tr -d '[:space:]')"
        FILEPATH="$SHARE_PATH/$filename"

        # Check if file exists AND has correct content
        if [[ ! -f "$FILEPATH" ]]; then
            echo "$LOG_PREFIX ALERT: Required share file MISSING: $filename — recreating"
            RESTORE_NEEDED=true
        elif ! echo "$expected_content" | diff - "$FILEPATH" &>/dev/null; then
            echo "$LOG_PREFIX ALERT: Share file MODIFIED: $filename — restoring"
            RESTORE_NEEDED=true
        else
            RESTORE_NEEDED=false
        fi

        if [[ "$RESTORE_NEEDED" == "true" ]]; then
            printf "%s\n" "$expected_content" > "$FILEPATH"
            chown root:smbgroup "$FILEPATH"
            chmod 0664 "$FILEPATH"
            restorecon "$FILEPATH" 2>/dev/null || true    # Re-apply SELinux context
            echo "$LOG_PREFIX RECOVERED: Restored $filename"
        fi
    done < "$SHARE_FILES_LIST"
fi

# =============================================================================
# 6. SELinux STATUS CHECK — alert if someone disabled it
# =============================================================================
# Red team LOVES to disable SELinux because it removes a major defense layer.
# "setenforce 0" sets it to Permissive (still logs but doesn't enforce).
# Editing /etc/selinux/config disables it permanently on next boot.
if [[ "$(getenforce 2>/dev/null)" != "Enforcing" ]]; then
    echo "$LOG_PREFIX ALERT: SELinux is NOT enforcing! Status: $(getenforce) — re-enabling"
    setenforce 1 2>/dev/null && echo "$LOG_PREFIX RECOVERED: SELinux set to Enforcing" \
                             || echo "$LOG_PREFIX FAILED: Could not re-enable SELinux"
fi

# =============================================================================
# 7. CHATTR LOCK GUARDIAN — re-lock configs if someone removed +i flag
# =============================================================================
# Red team needs to run chattr -i before modifying locked files.
# After tampering, they may leave the file unlocked. Re-lock it.
for config_file in /etc/ssh/sshd_config /etc/samba/smb.conf; do
    if [[ -f "$config_file" ]]; then
        # lsattr shows file attributes; 'i' flag means immutable
        if ! lsattr "$config_file" 2>/dev/null | grep -q '\-i\-'; then
            echo "$LOG_PREFIX INFO: Re-locking $config_file with chattr +i"
            chattr +i "$config_file" 2>/dev/null || true
        fi
    fi
done

# Script completes silently if all checks pass (no output = nothing to worry about)
exit 0
