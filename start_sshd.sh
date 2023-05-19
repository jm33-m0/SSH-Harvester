#!/bin/bash

[[ "$EUID" -eq 0 ]] || {
    echo "Run me as root"
    exit 0
}
sshd_dir="$(pwd)"

start_sshd() {
    [[ -d "/var/empty" ]] || mkdir /var/empty &&
        (
            cd "$sshd_dir" &&
                "$sshd_dir/sshd" -f "/etc/ssh/sshd_config" -h "$sshd_dir/ssh_host_rsa_key" -D -p 2222
        )
}

build() {
    apt update &&
        apt install -y autoconf &&
        apt install libedit-dev libselinux1-dev libpam0g-dev zlib1g-dev libfido2-dev libssl-dev &&
        autoreconf &&
        ./configure --with-pam --with-selinux --with-libedit &&
        make -j 2
}

[[ -f "$sshd_dir/sshd" ]] || build
start_sshd
