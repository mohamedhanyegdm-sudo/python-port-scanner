# Python Port Scanner

A small, multi-threaded TCP port scanner written in pure Python (standard library only, no installs).
I built it as a learning project for network security basics.

> **Ethical use:** scan only systems you own or have written permission to test.
> Safe targets for practice: `localhost`, `127.0.0.1`, or `scanme.nmap.org` (Nmap's public test host, scan politely).

## Features

- TCP connect scan using a thread pool (default 100 threads)
- Port lists and ranges: `22,80,443`, `1-1000`, or mixed `22,80,8000-8100`
- `--common` shortcut for 27 frequently used ports
- Adjustable timeout and thread count
- Basic banner grabbing (`-b`), including a small HTTP `HEAD` request on web ports
- Simple service-name mapping (built-in table, then the OS services database)
- Text or JSON output
- Tiny test suite (`unittest`)

## Requirements

Python 3.8+. Nothing else.

## Usage

```bash
python3 portscanner.py HOST [-p PORTS | --common] [-t TIMEOUT] [-T THREADS] [-b] [-o text|json]
```

| Option | Meaning |
|---|---|
| `-p, --ports` | Ports to scan (default `1-1024`) |
| `--common` | Scan common ports only |
| `-t, --timeout` | Seconds to wait per port (default `1.0`) |
| `-T, --threads` | Number of threads (default `100`) |
| `-b, --banner` | Try to read a service banner |
| `-o, --output` | `text` (default) or `json` |

### Examples

```bash
python3 portscanner.py localhost                    # ports 1-1024
python3 portscanner.py localhost -p 1-9000 -b       # with banners
python3 portscanner.py scanme.nmap.org --common     # common ports
python3 portscanner.py 127.0.0.1 -p 22,80,443 -o json
```

Example output (a local test web server on port 8000):

```
[!] Use only on systems you own or are authorized to test.
Scanning localhost (127.0.0.1), 9000 ports
PORT    STATE   SERVICE       BANNER
8000    open    http-alt      HTTP/1.0 200 OK
Done: 1 open of 9000 scanned in 0.22s
```

## How it works

1. The port list is parsed (`1-100,443` becomes a list of numbers).
2. A thread pool tries `socket.create_connection()` on many ports at the same time.
3. If the connection succeeds, the port is **open**. If it is refused or times out, it is skipped.
4. For open ports the scanner looks up a service name and, with `-b`, reads the first line the service sends.
5. Results are sorted and printed as text or JSON.

This is a full TCP connect scan, so it is simple and needs no admin rights, but it is easy to detect and slower than SYN scanners like Nmap. Filtered and closed ports are not told apart.

## Tests

```bash
python3 -m unittest -v
```

## Limitations

- TCP only (no UDP), IPv4 name resolution
- No OS or version detection
- Banner grabbing is basic; many services send nothing until asked

## Disclaimer

For educational use and authorized testing only. Scanning systems without permission may be illegal. The author is not responsible for misuse.

## License

MIT, see [LICENSE](LICENSE).
