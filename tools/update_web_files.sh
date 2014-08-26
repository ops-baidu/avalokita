#!/bin/sh

mkdir -p packages &&

# rpm
mkdir -p yum/Packages &&
cd yum &&
createrepo . &&
cd .. &&

# deb
mkdir -p deb/dists/all/main/{binary-amd64,binary-i386} &&
cd deb/dists/all/main/binary-i386/ &&
echo -n | gzip -f > Packages.gz &&
cd ../binary-amd64 && {
    ls *.deb >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        for i in *.deb; do
            ar p $i control.tar.gz | tar -xzf  - control -O &&
                echo Filename: $i &&
                echo Size: $(cat $i | wc -c) &&
                echo MD5sum: $(md5sum $i | cut -f1 -d ' ') &&
                echo
        done | gzip -f > Packages.gz
    else
        echo -n | gzip -f > Packages.gz
    fi
}
