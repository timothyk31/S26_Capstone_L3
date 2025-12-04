#!/bin/bash
# Setup SSH key authentication for a target host (example script for legacy flows).
#
# NOTE: This script uses placeholder credentials. Replace HOST/USER and
# BECOME_PASSWORD with values appropriate for your lab environment. Do NOT
# commit real passwords.

set -e

HOST="192.168.135.128"
USER="skanda"
KEY_PATH="$HOME/.ssh/mertcis_key"
BECOME_PASSWORD="CHANGE_ME_SUDO_PASSWORD"

echo "======================================================================"
echo "SSH Key Setup for mertcis (legacy example)"
echo "======================================================================"
echo ""
echo "This will set up SSH key authentication so you don't need passwords"
echo ""

# Check if key already exists
if [ -f "$KEY_PATH" ]; then
    echo "✓ SSH key already exists: $KEY_PATH"
    echo ""
    read -p "Do you want to use the existing key? (y/n): " use_existing
    if [ "$use_existing" != "y" ]; then
        echo "Generating new key..."
        ssh-keygen -t rsa -b 4096 -f "$KEY_PATH"
    fi
else
    echo "Generating SSH key..."
    ssh-keygen -t rsa -b 4096 -f "$KEY_PATH" -N ""
    echo "✓ Key generated: $KEY_PATH"
fi

echo ""
echo "Copying key to target host..."
echo "You'll be prompted for the user's SSH password."
echo ""

ssh-copy-id -i "${KEY_PATH}.pub" ${USER}@${HOST}

echo ""
echo "Testing key authentication..."
if ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no ${USER}@${HOST} "echo 'SSH key works!'"; then
    echo ""
    echo "✓ SSH key authentication working!"
    echo ""
    echo "Now updating inventory.yml example..."

    # Update inventory.yml to use key (example only)
    cat > inventory.yml << EOF
all:
  hosts:
    mertcis:
      ansible_host: ${HOST}
      ansible_port: 22
      ansible_user: ${USER}
      ansible_ssh_private_key_file: ${KEY_PATH}
      ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_password: ${BECOME_PASSWORD}
EOF

    echo "✓ inventory.yml updated to use SSH key (with placeholder become password)"
    echo ""
    echo "Testing Ansible connection..."
    if ansible -i inventory.yml all -m ping; then
        echo ""
        echo "======================================================================"
        echo "✓ Setup Complete!"
        echo "======================================================================"
        echo ""
        echo "You can now run (legacy examples):"
        echo "  python legacy_files/test_end_to_end.py"
        echo "  python legacy_files/qa_loop.py --host ${HOST} --user ${USER} --key ${KEY_PATH} --inventory inventory.yml"
        echo ""
    else
        echo ""
        echo "⚠ Ansible test failed, but SSH key should work for OpenSCAP scans"
    fi
else
    echo ""
    echo "✗ SSH key test failed"
    echo "You may need to check SSH server configuration on the target"
fi


