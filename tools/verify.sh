[ ! -r "$1" ] && {
    echo "USAGE: $0 [data file] [signature file]"
    exit 1
}

openssl smime -verify -noverify -inform PEM -content $1 -out /dev/null

