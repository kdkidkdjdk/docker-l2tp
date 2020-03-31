# Dockerfile for L2TP/IPSec VPN Server based alpine
# Copyright (C) 2018 - 2019 Teddysun <i@teddysun.com>

FROM alpine:latest
LABEL maintainer="Teddysun <i@teddysun.com>, xzl2021 <xzl2021#hotmail.com>"

RUN apk add --no-cache ca-certificates openssl libreswan xl2tpd \
	&& ipsec initnss \
	&& wget -O /etc/init.d/ipsec https://raw.githubusercontent.com/xzl2021/docker-l2tp/master/ipsec \
	&& wget -O /usr/bin/l2tp https://raw.githubusercontent.com/xzl2021/docker-l2tp/master/l2tp.sh \
	&& wget -O /usr/bin/l2tpctl https://raw.githubusercontent.com/xzl2021/docker-l2tp/master/l2tpctl.sh \
	&& chmod 755 /etc/init.d/ipsec /usr/bin/l2tp /usr/bin/l2tpctl


VOLUME /lib/modules
VOLUME /etc/l2tp

EXPOSE 500/udp 4500/udp

CMD [ "l2tp" ]
