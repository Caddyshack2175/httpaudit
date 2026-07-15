# httpaudit
```bash

        ╦ ╦╔╦╗╔╦╗╔═╗╔═╗╦ ╦╔╦╗╦╔╦╗
        ╠═╣ ║  ║ ╠═╝╠═╣║ ║ ║║║ ║ 
        ╩ ╩ ╩  ╩ ╩  ╩ ╩╚═╝═╩╝╩ ╩ 

** For use against systems you own or have written authorisation to test. **

HTTPAudit - A powerful HTTP testing toolkit for security professionals:

• YAML template-based security testing
• HTTP fuzzing with placeholder support
• Clickjacking vulnerability detection
• Rate limiting bypass testing
• Proxy integration for Burp/ZAP
• Concurrent request handling
• Professional JSON reporting

Usage:
  httpaudit [command]

Available Commands:
  enhance-template Enhance Nuclei template with report metadata from JSON report
  framer           Test for clickjacking vulnerabilities by checking HTTP headers
  fuzzer           HTTP fuzzing tool with placeholder support
  headers          Check security headers on URLs or via fuzzing
  help             Help about any command
  nuclei           Run Nuclei templates and output in custom report format
  rate-limiter     Test API rate limiting with controlled concurrent requests
  stagger          HTTP fuzzing with batched requests and cooldown periods
  uri-gen          Generate URIs from directory structure for artifact discovery

Flags:
  -h, --help           help for httpaudit
  -p, --proxy string   Proxy URL (http://host:port)
  -q, --quiet          Quiet mode (suppress progress)
  -t, --timeout int    Request timeout in seconds (default 30)
  -v, --verbose        Verbose output
      --version        version for httpaudit

Use "httpaudit [command] --help" for more information about a command.

```
