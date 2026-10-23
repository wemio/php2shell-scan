#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP2Shell exposure and compromise-indicator scanner.

Covers CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global state).
This tool is defensive: it never sends exploit traffic.
"""

import argparse
import glob
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

TOOL_NAME = "php2shell_scan"
TOOL_VERSION = "1.0"

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

IOC_PATTERNS = [
    ("critical", re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I),
     "session.upload_progress 触发字段"),
    ("critical", re.compile(r"p2shell", re.I),
     "PHP2Shell 工具 multipart boundary 标记"),
    ("high", re.compile(r"B8RAT/1\.0", re.I),
     "已知攻击变体 User-Agent"),
    ("high", re.compile(r"wafjunk", re.I),
     "已知 OOM 填充字段"),
    ("high", re.compile(r"[A-Za-z0-9_]+\[k0\]\[k1\]", re.I),
     "深层嵌套数组字段（OOM 放大）"),
    ("high", re.compile(r"(exited on signal (?:11|6)|SIGSEGV|zend_mm_heap corrupted)", re.I),
     "PHP worker 崩溃或堆破坏"),
    ("medium", re.compile(r"Allowed memory size of \d+ bytes exhausted", re.I),
     "PHP 内存耗尽"),
    ("medium", re.compile(r"PHP Fatal error", re.I),
     "PHP Fatal error（需结合时间与请求上下文）"),
]

SUSPICIOUS_PHP = [
    (re.compile(r"\beval\s*\(", re.I), 3, "eval"),
    (re.compile(r"\bassert\s*\(", re.I), 2, "assert"),
    (re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", re.I), 2, "命令执行函数"),
    (re.compile(r"\b(?:base64_decode|gzinflate|str_rot13)\s*\(", re.I), 2, "编码/解码"),
    (re.compile(r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[", re.I), 1, "直接使用超全局变量"),
    (re.compile(r"\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(", re.I), 1, "文件写入"),
    (re.compile(r"preg_replace\s*\([^)]*/e", re.I), 3, "preg_replace /e"),
    (re.compile(r"\bcreate_function\s*\(", re.I), 2, "create_function"),
]

UPLOAD_DIRS = {"upload", "uploads", "tmp", "temp", "cache", "images", "image", "files", "data"}
SKIP_DIRS = {".git", ".svn", "node_modules", "vendor", "__pycache__"}

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


class Report:
    def __init__(self):
        self.findings = []

    def add(self, severity, category, message, target="", evidence=""):
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "target": str(target),
            "evidence": str(evidence).replace("\ufeff", "")[:500],
        })

    def count(self, severity):
        return sum(1 for f in self.findings if f["severity"] == severity)

    def summary(self):
        out = {s: self.count(s) for s in SEVERITY_ORDER}
        out["total"] = len(self.findings)
        if out["critical"]:
            out["verdict"] = "critical"
        elif out["high"]:
            out["verdict"] = "high"
        elif out["medium"] or out["low"]:
            out["verdict"] = "attention"
        else:
            out["verdict"] = "ok"
        return out


def normalize(text):
    return str(text).strip().lower() in ("1", "on", "true", "yes", "enabled")


def parse_version(text):
    m = re.search(r"PHP\s+(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        m = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def evaluate_version(version):
    if not version:
        return "unknown", "无法解析版本"
    major, minor, patch = version
    label = f"{major}.{minor}.{patch}"
    if (major, minor) in FIXED:
        fixed = FIXED[(major, minor)]
        if patch >= fixed:
            return "fixed", f"{label} 已包含修复（>= {major}.{minor}.{fixed}）"
        return "vulnerable", f"{label} 受影响（需 >= {major}.{minor}.{fixed}）"
    if (major, minor) < (8, 2):
        return "vulnerable", f"{label} 受影响且已 EOL，无上游官方修复"
    if (major, minor) > (8, 5):
        return "unknown", f"{label} 非受支持稳定分支或预发布版，需向厂商确认"
    return "unknown", f"{label} 无法判定"


def parse_size(text):
    if not text:
        return None
    m = re.match(r"^\s*(\d+)\s*([kmg])?\s*$", str(text), re.I)
    if not m:
        return None
    value = int(m.group(1))
    unit = (m.group(2) or "").lower()
    return value * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[unit]


def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return -1, str(exc)


def unique_paths(paths):
    seen = set()
    out = []
    for item in paths:
        try:
            path = Path(item).resolve()
        except Exception:
            continue
        key = str(path).lower()
        if key not in seen and path.exists():
            seen.add(key)
            out.append(path)
    return out


def find_php_binaries():
    names = ["php", "php-fpm", "php-cgi"]
    found = []
    for name in names:
        hit = shutil.which(name)
        if hit:
            found.append(hit)
    patterns = [
        "/usr/bin/php*", "/usr/local/bin/php*", "/usr/local/sbin/php*",
        "/usr/sbin/php-fpm*", "/opt/*/bin/php", "/opt/php*/bin/php",
        "/usr/local/php*/bin/php", "/www/server/php/*/bin/php",
        "/usr/local/lsws/lsphp*/bin/php",
        r"C:\php\php.exe", r"C:\xampp\php\php.exe", r"C:\phpstudy_pro\Extensions\php\*\php.exe",
        r"C:\wamp64\bin\php\php*\php.exe", r"C:\laragon\bin\php\php*\php.exe",
        r"C:\Program Files\PHP\php.exe", r"C:\Program Files (x86)\PHP\php.exe",
    ]
    for pattern in patterns:
        found.extend(glob.glob(pattern))
    binaries = []
    for path in unique_paths(found):
        if path.is_file() and not path.name.lower().endswith((".dll", ".ini", ".conf")):
            binaries.append(path)
    return sorted(binaries, key=lambda p: str(p).lower())


def php_probe(binary):
    basename = binary.name.lower()
    rc, out = run([str(binary), "-v"], timeout=8)
    version = parse_version(out)
    info = {
        "binary": str(binary),
        "kind": "fpm" if "fpm" in basename else ("cgi" if "cgi" in basename else "cli"),
        "version": version,
        "version_text": (out.strip().splitlines() or [""])[0],
        "sapi": None,
        "ini": None,
        "settings": {},
    }
    if info["kind"] != "cli":
        return info
    code = (
        "$k=['session.upload_progress.enabled','session.use_strict_mode','memory_limit',"
        "'post_max_size','upload_max_filesize','max_file_uploads','fatal_error_backtraces',"
        "'display_errors'];$s=[];foreach($k as $n){$s[$n]=ini_get($n);}"
        "echo json_encode(['version'=>PHP_VERSION,'sapi'=>PHP_SAPI,"
        "'ini'=>php_ini_loaded_file(),'scanned'=>php_ini_scanned_files(),'settings'=>$s]);"
    )
    rc, out = run([str(binary), "-d", "display_errors=0", "-r", code], timeout=8)
    try:
        start = out.find("{")
        payload = json.loads(out[start:]) if start >= 0 else {}
    except Exception:
        payload = {}
    if payload:
        info["version"] = parse_version(payload.get("version", "")) or info["version"]
        info["sapi"] = payload.get("sapi")
        info["ini"] = payload.get("ini")
        info["settings"] = payload.get("settings") or {}
    return info


def scan_ini_files(report):
    patterns = [
        "/etc/php/*/fpm/php.ini", "/etc/php/*/apache2/php.ini", "/etc/php/*/cli/php.ini",
        "/usr/local/etc/php/php.ini", "/etc/php.ini",
        r"C:\php\php.ini", r"C:\xampp\php\php.ini", r"C:\phpstudy_pro\Extensions\php\*\php.ini",
    ]
    for pattern in patterns:
        for raw in glob.glob(pattern):
            path = Path(raw)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if re.search(r"^\s*session\.upload_progress\.enabled\s*=\s*(0|Off|false)\b",
                         text, re.I | re.M):
                report.add("info", "ini", "session.upload_progress 已在 php.ini 中关闭", path)
            if re.search(r"^\s*fatal_error_backtraces\s*=\s*(0|Off|false)\b", text, re.I | re.M):
                report.add("info", "ini", "fatal_error_backtraces 已关闭", path)


def scan_fpm_pools(report):
    patterns = [
        "/etc/php/*/fpm/pool.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf",
        "/etc/php-fpm.d/*.conf", "/www/server/php/*/etc/php-fpm.d/*.conf",
        r"C:\php\php-fpm.d\*.conf",
    ]
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    for raw in unique_paths(files):
        path = Path(raw)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        joined = "\n".join(line for line in lines if not line.lstrip().startswith(";"))
        if not re.search(r"session\.upload_progress\.enabled\s*\]?\s*=\s*(0|off|false)",
                         joined, re.I):
            report.add("low", "fpm",
                       "FPM pool 未显式关闭 session.upload_progress；若全局 php.ini 已关闭可忽略",
                       path)
        if re.search(r"pm\.max_requests\s*=\s*(0|\d{3,})", joined, re.I):
            report.add("low", "fpm",
                       "pm.max_requests 较大或为 0，stale state 可跨更多请求保留", path)
        for m in re.finditer(r"php_(?:admin_)?value\s*\[memory_limit\]\s*=\s*([^\s;]+)",
                             joined, re.I):
            if m.group(1).strip() not in ("-1",):
                report.add("high", "fpm",
                           f"pool 内 memory_limit={m.group(1)}，保留了 OOM 触发条件", path)
        if re.search(r"php_(?:admin_)?(?:value|flag)\s*\[session\.upload_progress\.enabled\]"
                     r"\s*=\s*(0|off|false)", joined, re.I):
            report.add("info", "fpm", "pool 已关闭 session.upload_progress", path)


def detect_web_sapi(report):
    for exe in ("httpd", "apache2", "apachectl", "apache2ctl"):
        path = shutil.which(exe)
        if not path:
            continue
        rc, out = run([path, "-M"], timeout=8)
        if "php_module" in out:
            report.add("high", "sapi",
                       "检测到 Apache mod_php：这是本次漏洞最高风险的运行方式，"
                       "未认证请求可在应用代码执行前触发", path)
        break
    for exe in ("php-fpm", "php-fpm8.2", "php-fpm8.3", "php-fpm8.4", "php-fpm8.5"):
        hit = shutil.which(exe)
        if hit:
            report.add("info", "sapi", "检测到 PHP-FPM 可执行文件", hit)
            break
    rc, out = run(["systemctl", "list-units", "--type=service", "--no-pager"], timeout=8) \
        if shutil.which("systemctl") else (-1, "")
    for name in ("php-fpm", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm", "php8.5-fpm", "apache2", "httpd"):
        if re.search(rf"\b{re.escape(name)}\.service", out):
            report.add("info", "sapi", "检测到运行中的服务（升级后需重启）", name)


def audit_settings(report, info):
    status, detail = evaluate_version(info["version"])
    settings = info["settings"]
    target = info["binary"]
    severity = "critical" if status == "vulnerable" else "high"
    if status == "vulnerable":
        report.add("critical", "version", detail, target)
    elif status == "unknown":
        report.add("medium", "version", detail, target)
    else:
        report.add("info", "version", detail, target)

    if info["kind"] == "cli":
        report.add("info", "scope",
                   "CLI 的 php.ini 不必然等于 FPM/Apache 的配置，"
                   "请同时检查 pool 与 vhost 配置", target)

    if not settings:
        return status

    if normalize(settings.get("session.upload_progress.enabled")):
        config_severity = severity if status == "vulnerable" else (
            "medium" if status == "unknown" else "low")
        report.add(config_severity, "config",
                   "session.upload_progress.enabled 未关闭：CVE-2026-109619 的确认利用入口；"
                   "该字段在应用代码执行前由 PHP 解析", target,
                   f"session.upload_progress.enabled={settings.get('session.upload_progress.enabled')}")

    if not normalize(settings.get("session.use_strict_mode")):
        report.add("medium" if status == "vulnerable" else "low", "config",
                   "session.use_strict_mode 未开启，攻击者可指定任意 session id", target)

    memory_limit = settings.get("memory_limit")
    if memory_limit not in (None, "", "-1") and parse_size(memory_limit):
        report.add("high" if status == "vulnerable" else "info", "config",
                   "memory_limit 为有限值：CVE-2026-109618 依赖可控的内存耗尽失败；"
                   "临时缓解应通过不可覆盖配置设为 -1", target,
                   f"memory_limit={memory_limit}")

    if info["version"] and info["version"][:2] == (8, 5) \
            and normalize(settings.get("fatal_error_backtraces")):
        report.add("high" if status == "vulnerable" else "medium", "config",
                   "PHP 8.5 fatal_error_backtraces 开启：这是 CVE-2026-109619 的确认路径",
                   target)

    post_max = parse_size(settings.get("post_max_size"))
    if post_max and post_max > 32 * 1024 ** 2:
        report.add("medium", "config",
                   "post_max_size 偏大，给内存耗尽留下了空间（建议 8M/32M）", target,
                   f"post_max_size={settings.get('post_max_size')}")

    max_files = settings.get("max_file_uploads")
    if str(max_files).isdigit() and int(max_files) > 20:
        report.add("low", "config",
                   "max_file_uploads 偏大，建议收紧 multipart 段数量", target)

    if normalize(settings.get("display_errors")):
        report.add("low", "config",
                   "display_errors 开启，会放大报错与内存布局信息泄露", target)


def scan_local(report):
    binaries = find_php_binaries()
    if not binaries:
        report.add("high", "discovery",
                   "未在 PATH 与常见路径发现 PHP；若确认存在 Web 服务，请用 --remote 或检查容器")
    for binary in binaries:
        info = php_probe(binary)
        audit_settings(report, info)
    scan_ini_files(report)
    scan_fpm_pools(report)
    detect_web_sapi(report)


def http_get(url, timeout=8, insecure=False):
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "php2shell-scan/1.0 (defensive; no exploit)",
        "Accept": "*/*",
    })
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        body = exc.read(65536).decode("utf-8", "replace") if exc.fp else ""
        return exc.code, dict(exc.headers or {}), body


def scan_remote(report, url, timeout=8, insecure=False):
    try:
        status, headers, body = http_get(url, timeout=timeout, insecure=insecure)
    except Exception as exc:
        report.add("medium", "remote", f"请求失败：{exc}", url)
        return
    lower = {k.lower(): v for k, v in headers.items()}
    banner = " ".join([
        lower.get("server", ""), lower.get("x-powered-by", ""),
        lower.get("x-php-version", ""), body[:4096],
    ])
    version = parse_version(banner)
    if version:
        state, detail = evaluate_version(version)
        if state == "vulnerable":
            report.add("critical", "remote", detail, url, banner[:300])
        elif state == "unknown":
            report.add("medium", "remote", detail, url, banner[:300])
        else:
            report.add("info", "remote", detail, url)
    elif "phpsessid" in str(headers).lower():
        report.add("high", "remote",
                   "目标使用 PHP（PHPSESSID）且未暴露版本；仅凭 HTTP 无法排除受影响，"
                   "请在主机侧确认包版本", url)
    else:
        report.add("info", "remote",
                   "响应中未识别到 PHP 版本或会话 Cookie；不能据此排除风险", url)
    if lower.get("x-powered-by"):
        report.add("low", "remote", "X-Powered-By 泄露运行时信息，建议关闭", url,
                   lower["x-powered-by"])


def extract_date(line):
    m = re.search(r"(20\d{2})-(\d{2})-(\d{2})", line)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    m = re.search(r"\[(\d{1,2})/([A-Za-z]{3})/(\d{4}):", line)
    if m and m.group(2).lower() in MONTHS:
        try:
            return date(int(m.group(3)), MONTHS[m.group(2).lower()], int(m.group(1)))
        except ValueError:
            pass
    m = re.search(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}", line)
    if m and m.group(1).lower() in MONTHS:
        try:
            return date(datetime.now().year, MONTHS[m.group(1).lower()], int(m.group(2)))
        except ValueError:
            pass
    return None


def collect_log_files(paths):
    files = []
    for raw in paths:
        for item in (glob.glob(str(raw)) or [str(raw)]):
            p = Path(item)
            if p.is_file():
                files.append(p)
            elif p.is_dir():
                for child in p.rglob("*"):
                    try:
                        if child.is_file() and child.stat().st_size <= 256 * 1024 ** 2:
                            files.append(child)
                    except OSError:
                        continue
    return sorted(unique_paths(files), key=lambda x: str(x).lower())


def scan_logs(report, paths, since):
    files = collect_log_files(paths)
    if not files:
        report.add("medium", "logs", "未找到可扫描的日志文件", ", ".join(map(str, paths)))
        return
    scanned = 0
    hit_counts = {}
    totals = {}
    for path in files[:2000]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                scanned += 1
                for line in handle:
                    d = extract_date(line)
                    if d and since and d < since:
                        continue
                    for severity, pattern, label in IOC_PATTERNS:
                        if pattern.search(line):
                            totals[label] = totals.get(label, 0) + 1
                            key = (str(path), label)
                            if hit_counts.get(key, 0) < 20:
                                hit_counts[key] = hit_counts.get(key, 0) + 1
                                report.add(severity, "ioc", label, path, line.strip())
                            break
        except Exception as exc:
            report.add("low", "logs", f"读取失败：{exc}", path)
    report.add("info", "logs", f"已扫描 {scanned} 个日志文件", ", ".join(map(str, paths)))
    if totals:
        summary = "；".join(f"{label}={count}" for label, count in totals.items())
        report.add("info", "logs", f"IOC 命中总数（每文件最多展示 20 条）：{summary}")


def scan_webroot(report, roots, since, max_files):
    cutoff = datetime.combine(since, datetime.min.time(), tzinfo=timezone.utc).timestamp() \
        if since else 0
    seen = 0
    for raw in roots:
        root = Path(raw)
        if not root.is_dir():
            report.add("medium", "webroot", "目录不存在或不可读", root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            for name in filenames:
                if seen >= max_files:
                    report.add("medium", "webroot",
                               f"达到文件上限 {max_files}，结果可能不完整", root)
                    return
                if not name.lower().endswith((".php", ".phtml", ".php5", ".php7", ".phar")):
                    continue
                path = Path(dirpath) / name
                try:
                    stat = path.stat()
                except OSError:
                    continue
                recent = stat.st_mtime >= cutoff
                in_upload = any(part.lower() in UPLOAD_DIRS for part in path.parts)
                if not recent and not in_upload:
                    continue
                seen += 1
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")[:262144]
                except Exception:
                    continue
                hits = []
                score = 0
                for pattern, weight, label in SUSPICIOUS_PHP:
                    if pattern.search(text):
                        score += weight
                        hits.append(label)
                if in_upload and path.suffix.lower() in (".php", ".phtml", ".php5", ".php7"):
                    report.add("high", "webroot",
                               "上传/缓存目录中存在 PHP 文件，请立即隔离复核", path,
                               ", ".join(hits) or "无关键字命中")
                elif score >= 4:
                    report.add("high", "webroot",
                               "近期修改的 PHP 文件含多处可疑特征（可能是 webshell）", path,
                               ", ".join(hits))
                elif score >= 2:
                    report.add("medium", "webroot",
                               "近期修改的 PHP 文件含可疑特征，需人工复核", path,
                               ", ".join(hits))
    report.add("info", "webroot", f"已检查 {seen} 个候选 PHP 文件",
               ", ".join(map(str, roots)))


def emit(report, args):
    summary = report.summary()
    ordered = sorted(report.findings,
                     key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["category"]))
    if not args.quiet:
        print("=" * 68)
        print("PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 自查报告")
        print(f"时间(UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
        print(f"主机: {platform.node()} | 系统: {platform.system()} {platform.release()}")
        print("说明: 仅做版本、配置与日志自查，不发送任何利用流量")
        print("=" * 68)
        for f in ordered:
            prefix = {"critical": "[CRITICAL]", "high": "[HIGH]",
                      "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]"}[f["severity"]]
            print(f"{prefix} {f['message']}")
            if f["target"]:
                print(f"    target: {f['target']}")
            if f["evidence"]:
                evidence = " ".join(f["evidence"].split())
                print(f"    evidence: {evidence[:220]}")
        print("-" * 68)
        print("汇总: " + " ".join(f"{k}={v}" for k, v in summary.items() if k != "verdict"))
        if summary["verdict"] == "critical":
            print("结论: 存在可直接利用的暴露项，按“先降险、再升级、后取证”处理。")
        elif summary["verdict"] == "high":
            print("结论: 存在高风险项，尽快升级并复核配置。")
        elif summary["verdict"] == "attention":
            print("结论: 未发现致命项，但有需要处理/复核的配置或线索。")
        else:
            print("结论: 未发现明显暴露项；仍需确认未发现的运行时与容器。")
    if args.json:
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": " ".join(sys.argv),
            "summary": summary,
            "findings": ordered,
        }
        try:
            Path(args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
            if not args.quiet:
                print(f"JSON 已写入: {args.json}")
        except OSError as exc:
            print(f"JSON 写入失败: {exc}", file=sys.stderr)
    return 2 if summary["critical"] else (1 if summary["high"] or summary["medium"] else 0)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="PHP2Shell (CVE-2026-109618/109619) 暴露与入侵线索自查工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python php2shell_scan.py --local\n"
            "  python php2shell_scan.py --remote https://example.com --insecure\n"
            "  python php2shell_scan.py --logs /var/log/nginx /var/log/php* --since 2026-10-17\n"
            "  python php2shell_scan.py --webroot /var/www --since 2026-10-17 --json out.json\n"
        ))
    parser.add_argument("--local", action="store_true", help="检查本机 PHP 版本与配置")
    parser.add_argument("--remote", action="extend", nargs="+", default=[], metavar="URL",
                        help="检查远程 HTTP 响应（可重复）")
    parser.add_argument("--logs", action="extend", nargs="+", default=[], metavar="PATH",
                        help="扫描日志文件或目录（可重复）")
    parser.add_argument("--webroot", action="extend", nargs="+", default=[], metavar="PATH",
                        help="扫描 Web 根目录下的可疑 PHP 文件（可重复）")
    parser.add_argument("--since", default="2026-10-17",
                        help="日志/文件起始日期，默认 2026-10-17")
    parser.add_argument("--json", metavar="FILE", help="输出 JSON 报告")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP 超时秒数")
    parser.add_argument("--insecure", action="store_true", help="忽略 TLS 证书错误")
    parser.add_argument("--max-files", type=int, default=20000, help="Web 根目录文件上限")
    parser.add_argument("--quiet", action="store_true", help="不输出文本报告")
    return parser.parse_args(argv)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args(argv or sys.argv[1:])
    if not any([args.local, args.remote, args.logs, args.webroot]):
        args.local = True
    try:
        since = datetime.strptime(args.since, "%Y-%m-%d").date()
    except ValueError:
        print("--since 需要 YYYY-MM-DD 格式", file=sys.stderr)
        return 2
    report = Report()
    if args.local:
        scan_local(report)
    for url in args.remote:
        scan_remote(report, url, timeout=args.timeout, insecure=args.insecure)
    if args.logs:
        scan_logs(report, args.logs, since)
    for root in args.webroot:
        scan_webroot(report, [root], since, args.max_files)
    return emit(report, args)


if __name__ == "__main__":
    sys.exit(main())
