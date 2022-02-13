#!/bin/bash
cargo build
sudo setcap cap_net_admin=eip target/debug/thunder
sudo chmod 666 /sys/class/leds/sys_led/trigger
sudo chmod 666 /sys/class/leds/red_red/trigger
echo none > /sys/class/leds/sys_led/trigger
echo heartbeat > /sys/class/leds/red_red/trigger
target/debug/thunder &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid; echo none > /sys/class/leds/red_red/trigger" INT TERM
wait $pid
