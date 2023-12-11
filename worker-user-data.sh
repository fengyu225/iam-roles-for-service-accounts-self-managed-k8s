#!/bin/bash
set -x
sudo apt-get update
sudo apt-get install -y awscli
sudo apt-get install conntrack

# Determine the last octet of the private IP address
ip=$(hostname -I | awk '{ print $1 }')
last_octet=$(echo "${ip}" | awk -F '.' '{print $4}')

# Use the last octet to determine the index (2 or 3)
# Change this if the worker count is not 2
idx=$(( last_octet % 2 + 2 ))

sudo hostnamectl set-hostname node-$idx