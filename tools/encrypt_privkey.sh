#!/bin/sh

set -e
set -o pipefail

encrypt() {
    [ -r "privkey.pem" ] || {
        echo "No privkey.pem found."
        exit 1
    }

    for i in $(seq 1 ${password_count}); do
        echo "Input password $i:"

        if [ "$i" -eq 1 ]; then 
            data="$(cat privkey.pem | openssl base64 | openssl enc -aes-256-cbc -e | openssl base64)"
        else 
            data="$(echo ${data} | openssl enc -aes-256-cbc -e | openssl base64)"
        fi
    done

    echo -n "${data}" > privkey.pem.encried
}

decrypt() {
    wget ftp://getprod:getprod@product.scm.baidu.com:/data/prod-64/op/oped/cloudwatch/agent/agent_1-0-0_BL/output/privkey.pem.encried -O privkey.pem.encried
    # svn export https://svn.baidu.com/op/oped/cloudwatch/trunk/agent/privkey.pem.encried

    for i in $(seq 1 ${password_count}); do
        echo "Input password $((password_count - i + 1)):"

        if [ "$i" -eq 1 ]; then 
            data="$(cat privkey.pem.encried | openssl base64 -d | openssl enc -aes-256-cbc -d)"
        else 
            data="$(echo ${data} | tr ' ' '\n' | openssl base64 -d | openssl enc -aes-256-cbc -d)"
        fi
    done

    echo -n "${data}" | openssl base64 -d > privkey.pem
}

echo "USAGE: "
echo "    $0    : encrypt privkey.pem"
echo "    $0 -d : decrypt privkey.pem.encried"
echo "=========="
echo

echo 'Input password count:'
read password_count

if [ "$1" = "-d" ]; then
    decrypt
else
    encrypt
fi
