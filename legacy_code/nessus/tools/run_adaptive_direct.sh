#!/bin/bash
# Run adaptive agent with password provided via environment (for local testing)
#
# NOTE: Do NOT commit real passwords here. Set SUDO_PASSWORD in your shell
# environment before running this script:
#   export SUDO_PASSWORD="your_sudo_password"

if [ -z "$SUDO_PASSWORD" ]; then
  echo "SUDO_PASSWORD is not set. Please export it in your environment before running."
  exit 1
fi

python -B qa_agent_adaptive.py \
  --host 192.168.124.129  \
  --user llmagent1 \
  --sudo-password "$SUDO_PASSWORD" \
  --inventory inventory.yml \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --datastream /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml \
  --work-dir adaptive_qa_work \
  --max-vulns 5 \
  --min-severity 2 \
  --max-attempts 5 \
  --key C:\Users\coope\.ssh\id_ed25519 


