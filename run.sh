#!/bin/sh
mkdir -p /etc/l2tp/
cp ./l2tp.env /etc/l2tp/l2tp.env
docker run -d --privileged -p 500:500/udp -p 4500:4500/udp -v /etc/l2tp:/etc/l2tp -v /lib/modules:/lib/modules --restart=always --name l2tp -t l2tp:latest
