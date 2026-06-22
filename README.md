# ParamGhost 👻
*Built by baba01hacker*


ParamGhost is an advanced parameter discovery and fuzzing tool designed to uncover hidden or unused HTTP parameters by analyzing JavaScript sources and performing response difference correlation. 

By analyzing front-end code (such as variables, `FormData`, and `.append` calls) and cross-referencing with back-end responses, ParamGhost accurately identifies hidden debugging endpoints, admin flags, and other unexposed parameters.

## Features

- **JavaScript Parsing**: Extracts potential parameters from query strings, JSON keys, and dynamically built forms in `.js` files.
- **Smart Fuzzing**: Automatically correlates responses against a pre-established baseline to filter out dynamic content noise (like timestamps or CSRF tokens).
- **Concurrency Support**: Multi-threaded execution for blazing-fast parameter fuzzing.
- **Advanced Networking**: Supports proxies, custom headers, cookies, request delays, and automatic retries on rate limits/server errors.
- **JSON Output**: Export findings neatly to a `.json` file for integration into automation pipelines.
- **Beautiful Output**: Professional, colorized terminal UI with progress tracking.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Baba01hacker666/paramghost.git
   cd paramghost
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python3 paramghost.py -u <target_url> [options]
```

### Options

| Flag | Name | Description |
|---|---|---|
| `-u`, `--url` | Target URL | The base URL to scan (e.g. `http://example.com/app`). **(Required)** |
| `-w`, `--workers` | Workers | Number of concurrent workers (default: `10`). |
| `-t`, `--timeout` | Timeout | HTTP request timeout in seconds (default: `10`). |
| `-d`, `--delay` | Delay | Delay between requests in seconds (default: `0`). |
| `-W`, `--wordlist` | Wordlist | Custom wordlist file containing parameters to fuzz. |
| `-H`, `--header` | Header | Custom header (e.g. `-H "Authorization: Bearer token"`). Can be used multiple times. |
| `-c`, `--cookie` | Cookie | Custom cookies (e.g. `-c "session=123; user=admin"`). |
| `-x`, `--proxy` | Proxy | HTTP/HTTPS proxy (e.g. `-x http://127.0.0.1:8080`). |
| `--no-redirects` | No Redirects | Disable following HTTP redirects. |
| `-o`, `--output` | Output | Output file to save results in JSON format. |

### Example

Basic run:
```bash
python3 paramghost.py -u https://target.com/
```

Advanced run with authentication, proxy, and JSON export:
```bash
python3 paramghost.py -u https://target.com/ \
  -H "Authorization: Bearer xyz123" \
  -c "session_id=abcdef" \
  -x http://127.0.0.1:8080 \
  -o results.json
```

## Disclaimer

This tool is designed for educational and authorized security testing purposes only. Do not use ParamGhost against applications you do not have explicit permission to test.
