[ ! -r "$1" ] && {
    echo "USAGE: $0 [data file] [signature file]"
    exit 1
}

openssl smime -verify -noverify -inform PEM -in $2 -content $1 -certfile cert.pem -out /dev/null

