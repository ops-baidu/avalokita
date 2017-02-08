#!/usr/bin/env bash

openssl smime -sign -noattr -binary -md sha1 -inkey privkey.pem -signer cert.pem -nocerts -outform pem
