#!/bin/bash
# NCAE - CosmicGrace

# user_create.sh - Mass user creation with SSH key setup and security lockdown
# Usage: sudo ./user_create.sh users.txt "password"

set -e  # Exit on error

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (use sudo)."
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: sudo ./user_create.sh <users_file> <password>"
    echo "Example: sudo ./user_create.sh users.txt 'MySecurePass123'"
    exit 1
fi

USERS_FILE="$1"
PASSWORD="$2"
GROUP_NAME="authorized"
SSH_KEY_DIR="/tmp/ssh_keys_$$"  # Temporary directory for key generation

# Verify users file exists
if [ ! -f "$USERS_FILE" ]; then
    echo "[ERROR] Users file not found: $USERS_FILE"
    exit 1
fi

echo "[*] Starting user creation process..."

# Create temporary directory for SSH keys (secure)
mkdir -p "$SSH_KEY_DIR"
chmod 700 "$SSH_KEY_DIR"

# Generate a master SSH key pair for testing
echo "[*] Generating master SSH key pair..."
ssh-keygen -t ed25519 -f "$SSH_KEY_DIR/authorized_key" -N "" -C "blue_team_key" > /dev/null 2>&1

# Create authorized group if it doesn't exist
if ! getent group "$GROUP_NAME" > /dev/null 2>&1; then
    echo "[*] Creating group: $GROUP_NAME"
    groupadd "$GROUP_NAME"
else
    echo "[*] Group $GROUP_NAME already exists"
fi

# Create users from file
echo "[*] Creating users from $USERS_FILE..."
while IFS= read -r username || [ -n "$username" ]; do
    # Skip empty lines and comments
    [[ -z "$username" || "$username" =~ ^# ]] && continue
    
    # Trim whitespace
    username=$(echo "$username" | xargs)
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        echo "[!] User $username already exists, skipping..."
        continue
    fi
    
    # Create user with home directory
    echo "[+] Creating user: $username"
    useradd -m -s /bin/bash "$username"
    
    # Set password (done securely without exposing in process list)
    echo "$username:$PASSWORD" | chpasswd
    
    # Add user to authorized group
    usermod -a -G "$GROUP_NAME" "$username"
    
    # Create .ssh directory with correct permissions
    SSH_DIR="/home/$username/.ssh"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chown "$username:$username" "$SSH_DIR"
    
    # Create authorized_keys file
    AUTHKEYS="$SSH_DIR/authorized_keys"
    touch "$AUTHKEYS"
    
    # Add the public key to authorized_keys
    cat "$SSH_KEY_DIR/authorized_key.pub" >> "$AUTHKEYS"
    
    # Set strict permissions on authorized_keys
    chmod 600 "$AUTHKEYS"
    chown "$username:$username" "$AUTHKEYS"
    
    # Make files immutable to prevent tampering (requires root)
    # Note: This is extreme and may prevent future modifications
    chattr +i "$SSH_DIR"
    chattr +i "$AUTHKEYS"
    
    echo "[+] User $username configured successfully"
done < "$USERS_FILE"

echo ""
echo "[*] Locking down authorized group..."

# Lock the group from modification (remove write permissions from group)
chmod g-w /etc/group
chmod g-w /etc/gshadow

# Make group immutable
# Note: This prevents group changes and may complicate user management
chattr +i /etc/group
chattr +i /etc/gshadow

echo "[+] Group locked"

echo ""
echo "[*] Securing shadow file..."
# Protect shadow file (password hashes)
# Note: chmod 000 + immutable prevents password changes; may break passwd tool
chmod 000 /etc/shadow
chattr +i /etc/shadow

echo ""
echo "=========================================="
echo "[✓] User creation complete!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Group: $GROUP_NAME (LOCKED)"
echo "  - SSH keys stored in: $SSH_KEY_DIR"
echo "  - Public key: $SSH_KEY_DIR/authorized_key.pub"
echo "  - Private key: $SSH_KEY_DIR/authorized_key (KEEP SAFE)"
echo ""
echo "Next steps:"
echo "  1. Copy the private key to your testing machine:"
echo "     scp root@<target>:$SSH_KEY_DIR/authorized_key ~/.ssh/"
echo "  2. Set permissions: chmod 600 ~/.ssh/authorized_key"
echo "  3. Test SSH: ssh -i ~/.ssh/authorized_key username@<target>"
echo ""
echo "[!] WARNING: SSH key files are in $SSH_KEY_DIR"
echo "[!] Back them up before cleaning up this directory"
echo "[!] The temp directory will be removed after this message."

# Cleanup temp directory (optional; comment out if you want to keep it)
rm -rf "$SSH_KEY_DIR"
echo "[*] Temp SSH key directory cleaned up."