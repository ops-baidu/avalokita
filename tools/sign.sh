openssl smime -sign -noattr -binary -md sha1 -inkey privkey.pem -signer cert.pem -outform pem
