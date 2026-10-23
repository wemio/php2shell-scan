# php2shell-scan

> Defensive exposure and compromise-indicator scanner for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619).
>
> 面向 PHP2Shell 漏洞的防御性自查工具：检查 PHP 版本、危险配置、日志 IOC 与可疑 PHP 文件，**不发送任何利用流量**。

PHP2Shell is a pair of critical PHP runtime vulnerabilities disclosed on 21 October 2026. Both can lead to unauthenticated remote code execution. This tool helps operators answer three questions quickly:

1. Which PHP runtimes are installed, and are they fixed?
2. Are the risky `session.upload_progress` / OOM-related settings still in place?
3. Do logs or web roots show signs of exploitation?

It is not an exploit, a vulnerability scanner, or a replacement for EDR/WAF.

---

## Requirements

- Python 3.8+
- No third-party dependencies
- Works on Linux, Windows, and macOS

## Quick start

```bash
git clone https://github.com/wemio/php2shell-scan.git
cd php2shell-scan
python php2shell_scan.py --local
```

Or download `php2shell_scan.py` and run it directly.

## Usage

```bash
# Check local PHP binaries, SAPI, php.ini, FPM pools, Apache mod_php
python php2shell_scan.py --local

# Check an HTTP endpoint (normal GET only)
python php2shell_scan.py --remote https://example.com

# Scan logs for request/host indicators occurred since 2026-10-17
python php2shell_scan.py --logs /var/log/nginx /var/log/php8.3-fpm.log \
  --since 2026-10-17

# Scan a web root for recently modified PHP files and webshell heuristics
python php2shell_scan.py --webroot /var/www --since 2026-10-17

# Combine modes and write a JSON report
python php2shell_scan.py --local --remote https://example.com \
  --logs /var/log/nginx --webroot /var/www --json report.json
```

### Options

| Option | Description |
|---|---|
| `--local` | Inspect local PHP binaries and server configuration |
| `--remote URL [URL ...]` | Inspect HTTP responses; sends a normal GET only |
| `--logs PATH [PATH ...]` | Scan log files/directories for IOCs |
| `--webroot PATH [PATH ...]` | Scan a web root for suspicious/recent PHP files |
| `--since YYYY-MM-DD` | Earliest date for logs/files (default `2026-10-17`) |
| `--json FILE` | Write a machine-readable report |
| `--timeout SECONDS` | HTTP timeout (default `8`) |
| `--insecure` | Ignore TLS certificate errors (remote mode) |
| `--max-files N` | Web-root candidate limit (default `20000`) |
| `--quiet` | Suppress the text report |

If no mode is given, `--local` is used.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No obvious exposure found |
| `1` | Medium/high findings or IOCs requiring review |
| `2` | Critical finding (vulnerable/EOL PHP or confirmed log IOC) |

## What it checks

### Local

- PHP CLI/FPM/CGI binaries in `PATH` and common install locations
- Version against the fixed releases
- `session.upload_progress.enabled`
- `session.use_strict_mode`
- `memory_limit`, `post_max_size`, `max_file_uploads`
- PHP 8.5 `fatal_error_backtraces`
- FPM pool overrides and `pm.max_requests`
- Apache `php_module` (mod_php) presence
- Running `php-fpm` / `apache2` / `httpd` services

### Logs

- `PHP_SESSION_UPLOAD_PROGRESS`
- `p2shell` boundary marker
- `B8RAT/1.0` user agent
- `wafjunk` OOM padding field
- Deeply nested array field names such as `f0[k0][k1]`
- Worker crashes: `signal 11`, `signal 6`, `SIGSEGV`, `zend_mm_heap corrupted`
- PHP OOM and fatal errors

### Web root

- PHP files modified since the cutoff date
- PHP files inside upload/cache/temp directories
- Heuristic webshell indicators (`eval`, command execution, encoded payloads, etc.)

## Fixed versions

| Branch | Affected | Fixed |
|---|---|---|
| PHP 8.5 | `< 8.5.12` | **8.5.12** |
| PHP 8.4 | `< 8.4.27` | **8.4.27** |
| PHP 8.3 | `< 8.3.36` | **8.3.36** |
| PHP 8.2 | `< 8.2.35` | **8.2.35** |
| PHP 8.1 and older | all | No upstream release; use vendor backport or upgrade |

> Updating PHP is the only complete fix. Configuration changes only reduce exposure to known paths.

## Example output

```text
====================================================================
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 自查报告
时间(UTC): 2026-10-23T00:15:17+00:00
说明: 仅做版本、配置与日志自查，不发送任何利用流量
====================================================================
[CRITICAL] session.upload_progress.enabled 未关闭：CVE-2026-109619 的确认利用入口
    target: ...\php7.4.3nts\php.exe
    evidence: session.upload_progress.enabled=1
[CRITICAL] 7.4.3 受影响且已 EOL，无上游官方修复
[HIGH] memory_limit 为有限值：CVE-2026-109618 依赖可控的内存耗尽失败
    evidence: memory_limit=1000M
[MEDIUM] session.use_strict_mode 未开启
--------------------------------------------------------------------
汇总: critical=3 high=1 medium=2 low=1 info=1 total=8
结论: 存在可直接利用的暴露项，按“先降险、再升级、后取证”处理。
```

## Limitations

- CLI `php.ini` may differ from the FPM/Apache configuration. Check pool and vhost settings manually.
- Remote PHP versions are often hidden. An inconclusive remote result does not mean the host is safe.
- Log formats vary; the regexes can miss or over-report. Check WAF/PCAP/EDR when possible.
- Webshell detection is heuristic and can flag legitimate code.
- This tool does not exploit anything and cannot prove a host is clean.

## Safety

- `--remote` sends only a normal `GET` request with a defensive user agent.
- Use `--remote` only against systems you own or are authorized to test.
- Review findings before deleting files or blocking IPs; some indicators may be shared infrastructure.

## References

- PHP security advisory, 21 Oct 2026: <https://www.php.net/archive/2026.php#2026-10-21-5>
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618): <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619): <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- Rapid7 analysis: <https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/>
- Tenable FAQ: <https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote>
- CIRCL TR-102: <https://www.circl.lu/pub/tr-102/>

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with the PHP project.
