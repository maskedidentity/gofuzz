GoFuzz - Advanced URL Fuzzing/Testing Tool (using curl)

Two modes available:
  1. FUZZ mode: Fuzz URLs with a wordlist
  2. HTTPX mode: Test list of full URLs

FUZZ Mode (fuzzing):
  -FUZZ <url>       Target URL with FUZZ placeholder (required)
  -w, --wordlist    Wordlist file path (required)
  -r, --rate        Rate limit in requests per second (default: 10)
  -rs, --resolvers  Resolver file with IP addresses (one per line)

HTTPX Mode (testing URLs):
  -HTTPX <file>     File containing URLs to test (one per line)
  -r, --rate        Rate limit (default: 10)
  -rs, --resolvers  Resolver file with IP addresses

Common Options:
  -h, --help        Show this help message

Examples:
  FUZZ mode:
    ./gofuzz -FUZZ 'http://example.com/FUZZ' -w wordlist.txt
    ./gofuzz -FUZZ 'https://target.com/api/v1/FUZZ' -w paths.txt -rate 20
  HTTPX mode:
    ./gofuzz -HTTPX urls.txt
    ./gofuzz -HTTPX urls.txt -rate 50 -resolvers dns_servers.txt

Note: This tool uses curl internally. Make sure curl is installed.
