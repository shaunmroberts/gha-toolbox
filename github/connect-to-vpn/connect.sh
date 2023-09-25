#!/bin/bash
set -e

sudo apt-get update
sudo apt-get --assume-yes --no-install-recommends install openvpn

echo VPV Client Install Complete

echo "$INPUT_VPN_CONFIG" > github_action.ovpn
echo "$INPUT_DEV_PEM" > dev.pem
chmod 600 dev.pem

sudo openvpn --config "github_action.ovpn" --log "vpn.log" --daemon

until ping -c1 172.26.3.201; do sleep 2; done