#!/bin/bash
set -x
sudo apt-get update
sudo apt-get install -y awscli

sudo apt-get install conntrack

sudo hostnamectl set-hostname node1

sudo apt-get install -y nginx