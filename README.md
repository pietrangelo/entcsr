# Compile instructions

We presume you are compiling for an AMD64 architecture

### Linux

`env GOOS=linux GOARCH=amd64 go build -o entcsr-lnx -tags osusergo,netgo entcsr.go`

### MAC OSX

`env GOOS=darwin GOARCH=amd64 go build -o entcsr-osx -tags osusergo,netgo entcsr.go`

### Windows

`env GOOS=windows GOARCH=amd64 go build -o entcsr-win.exe -tags osusergo,netgo entcsr.go`

## How to use

`./entcsr cert-name` This will produce two files:

- cert-name-key.key -> the private key
- cert-name-cert-sign-request.csr -> the certificate signing request
- cert-name-cert.crt -> the certificate
