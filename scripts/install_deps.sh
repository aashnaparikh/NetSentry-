#!/bin/bash
set -e

apt-get update
apt-get install -y libpcap-dev libgtest-dev cmake build-essential g++

echo "Dependencies installed successfully"
