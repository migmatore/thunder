#!/bin/bash
cargo build
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo setcap cap_net_admin=eip target/debug/thunder
sudo chmod 666 /sys/class/leds/white\:status/trigger
sudo chmod 666 /sys/class/leds/red\:status/trigger
echo none > /sys/class/leds/white\:status/trigger
echo heartbeat > /sys/class/leds/red\:status/trigger
target/debug/thunder &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid; echo none > /sys/class/leds/red\:status/trigger" INT TERM
wait $pid
