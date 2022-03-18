![alt text](https://github.com/elefr3n/real_ip_discover/blob/master/sample.gif?raw=true)
# Description
This tool helps you to find the server real ip address protected behind services like **Cloudflare, Akamai, and others WAF/CDN services**... <br /> <br />
**More explained post about this tool:** <br /> https://infosecwriteups.com/find-real-website-ip-bruteforcing-ipv4-ranges-c1e9ab2941e7
# How it works?
Giving a hostname (ex: site.com), a website html match (ex: "welmcome to site.com") and an ipv4 addresses or range list, this tool will send http/s requests to all ipv4 addresses checking if any of them responds with the match.

# How can I get possibles ipv4 ranges?
There exists a lot of ways to find possible ipv4 ranges where can be hosted the real server ip address, here I expose some:
 - Search target company ipv4 ranges/addresses in online services like ipv4info.com
 - Shodan, Censys...
 - Get ranges of the ipv4 addresses exposed in subdomains
 - Get ranges of ipv4 addresses exposed in emails raw data
 - Try to get more ipv4 addresses in dns history

# Usage
Positional and optional arguments:
```
positional arguments:
  hostname              Ex: site.com
  target_list           List of ip addresses or ranges | Ex: 0.0.0.0/24,5.5.5.5,6.6.6.6
  match                 Ex: "welcome to site.com"

optional arguments:
  -h, --help            show this help message and exit
  -u URI, --uri URI     Ex: /en/index.aspx
  -t THREADS, --threads THREADS
  -T TIMEOUT, --timeout TIMEOUT
  -v, --verbose         Verbose mode
```

Example command:
```sh
./real_ip_discover.py "site.com" 0.0.0.0/24 "<title>Welcome to site.com"
```
