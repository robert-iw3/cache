#!/usr/bin/env bash

systemctl daemon-reload
systemctl enable linux-sentinel.timer
systemctl start linux-sentinel.timer

podman build -t linux-sentinel .

podman run -d --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH --cap-add SYS_PTRACE \
    --network host -v /var/log/linux-sentinel:/var/log/linux-sentinel linux-sentinel