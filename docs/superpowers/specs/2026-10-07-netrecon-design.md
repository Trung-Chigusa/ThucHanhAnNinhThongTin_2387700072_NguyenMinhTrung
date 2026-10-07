# NetRecon - Design Specification

## Goal

Build the NetRecon portion of Lab 03 as a local Python application for reviewing explicitly authorized private lab hosts. It provides bounded TCP/UDP checks, banner and service hints, a read-only local neighbor-cache view, a small localhost web UI, and local JSON reports.

## Context and placement

- The assignment source is `Buổi 3/lab-03.pdf`.
- NetRecon is separate from `Buổi 3/secure-chat/` and will live in `Buổi 3/netrecon/`.
- The PDF contains examples of public-target and stealth scanning, a weak port-to-CVE checker, SMTP mail delivery, and a Flask server exposed on all interfaces. This implementation will not reproduce those behaviors.
- This is a Windows-friendly classroom lab tool, not an Internet-facing service or a general-purpose vulnerability scanner.

## Scope and target validation

- A scan accepts exactly one literal IPv4 or IPv6 host address. Hostnames, URLs, CIDR targets, ranges, subnet sweeps, and implicit DNS resolution are rejected.
- Every target must be both inside the configured allowlist and inside one of these private ranges: IPv4 loopback `127.0.0.0/8`, RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; IPv6 loopback `::1/128` or unique-local `fc00::/7`.
- The default allowlist contains only `127.0.0.1/32` and `::1/128`. An operator may add private lab networks in a local `.env` file. Public, link-local, multicast, unspecified, and other non-listed address classes remain out of scope even if entered in configuration.
- A blocklist overrides the allowlist. Scope checks run before a socket is created. Web requests cannot change the configured allowlist or blocklist.
- The allowlist and blocklist are parsed as IP addresses or networks and validated at startup. Invalid or overly broad non-private entries fail closed.

## Scan behavior and limits

- TCP checks use ordinary full connections. There is no raw-packet, SYN, FIN, Xmas, idle, decoy, fragmentation, proxy, or evasion mode.
- UDP checks send only an empty datagram. A response indicating an unreachable port may be reported as closed; silence is reported as `open|filtered` or `no_response`, never as closed.
- Ports are explicit integers or ranges from 1 through 65535, with at most 128 distinct ports per run. The default list is `22,80,443`.
- Probe rate defaults to 2 probes per second and can be configured only from 1 to 10 probes per second. Concurrent probes are capped at 4. Per-probe timeout is bounded to 0.2–3 seconds.
- A run stops on cancellation or an internal error without silently expanding its target or port set.
- Banner collection reads at most 512 bytes from a completed TCP connection with a short timeout and sends no application data. Empty or unavailable banners are reported as unknown.
- Service names are hints from the local service-name table and observed banners. No Nmap fingerprinting database or active exploit checks are used.

## Components

- `config.py` loads defaults and local `.env` settings for allowlist, blocklist, timeouts, rate, and concurrency.
- `modules/scope.py` validates target and configured network scope before network activity.
- `modules/filter_utils.py` handles port parsing and blocklist precedence.
- `modules/port_scanner.py` performs rate-limited TCP connect checks and minimal UDP probes.
- `modules/banner_grabber.py` reads bounded server greetings without sending a payload.
- `modules/service_detector.py` adds conservative service-name and banner hints.
- `modules/network_mapper.py` reads the host's existing ARP/neighbor cache only; it does not discover or probe hosts.
- `modules/vuln_checker.py` emits clearly labeled exposure-review notes for limited cases such as plaintext services. It does not map ports to CVEs, exploit services, or claim that a host is vulnerable.
- `modules/reporting.py` creates a timestamped JSON report with scan parameters, scope decision, observations, and limitations. Reports contain no credentials or private keys.
- `cli.py` provides explicit single-target scans and a read-only neighbor-cache view.
- `app.py` provides the local web interface and downloadable JSON report.
- `templates/` and `static/` hold the minimal UI. The UI displays the current scope and rate limit and rejects hostnames, ranges, and out-of-scope addresses.
- `tests/` covers scope, filters, rate bounds, result interpretation, report structure, and local-only integration behavior.

## Web and data handling

- The Flask app binds only to `127.0.0.1:5000`, with debug mode and the reloader disabled. It has no option to bind to `0.0.0.0` or a public interface.
- Scan submission requires a form token and applies the same scope, port-count, timeout, and rate checks as the CLI.
- The web UI can download a JSON report. It does not accept or send email, and there is no SMTP module, credential field, or mail configuration.
- `.env`, generated reports, and rotating local logs are ignored by Git. `.env.example` contains only safe loopback defaults and comments; no credential from the supplied PDF is copied into the project.
- Logs record scan lifecycle and status, not request secrets or raw packet data. Reports stay local unless the operator manually copies them.

## Verification and acceptance

1. Unit tests prove public, hostname, CIDR-target, blocklisted, and non-allowlisted inputs are rejected before any socket operation.
2. Tests verify the configured rate, concurrency, timeout, port-count, and response-size limits cannot be exceeded through CLI or web inputs.
3. TCP and UDP interpretation tests distinguish open, closed, filtered, and no-response states without treating UDP silence as proof of closure.
4. Local integration tests bind only to loopback and confirm a bounded TCP check, a UDP no-response result, and JSON report generation.
5. Neighbor-cache tests parse saved Windows-style `arp -a` output without invoking a scan or changing system state.
6. A web smoke check confirms the server is reachable at `127.0.0.1` and the same out-of-scope requests are rejected as in the CLI.
7. Repository checks confirm `.env`, reports, logs, and credentials are not tracked.

## Out of scope

- Public targets, domain resolution, multi-host or subnet scans, stealth/evasion, raw-packet scans, Nmap integration, brute force, exploitation, or CVE claims based only on a port number.
- SMTP or any other outbound messaging.
- Remote web access, user accounts, cloud services, persistent scan databases, or uploading reports.
- Changes to the separate SecureChat application.
