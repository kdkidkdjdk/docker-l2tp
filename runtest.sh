#!/bin/sh
mkdir -p /etc/l2tp/
docker run --privileged -p 500:500/udp -p 4500:4500/udp -v /etc/l2tp:/etc/l2tp -v /lib/modules:/lib/modules --name l2tp  -it alpine:latest
