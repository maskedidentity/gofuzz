GoFuzz - Advanced URL Fuzzing/Testing Tool (using curl)

to install this tool, use these commands

-> git clone https://github.com/maskedidentity/gofuzz.git
-> cd gofuzz
-> go mod download
-> go build
-> sudo mv gofuzz /usr/local/bin/gofuzz (now you can run gofuzz in any directory)


USAGE

FUZZ MODE
-> gofuzz -FUZZ 'https://www.google.com/FUZZ' -w (wordlist) -r (rate limit)

HTTPX MODE
-> gofuzz -HTTPX -w (urls file) -r (rate limit)

