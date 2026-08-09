# -*- coding: utf-8 -*-
"""Grok 4.5 功能测试：粘贴新注册账号的 token，自动转 grok auth 并跑 `-p "hi"` 验证。

支持三种输入（也可给文件路径，读第一行内容）：
  1. keys/token.txt 的 JSON 行（含 access_token / refresh_token / id_token / email）
  2. keys/sso.txt 一行：email----sso----sso_rw（自动 device flow 换 token）
  3. 已经转换好的 grok auth.json（含 "https://auth.x.ai::…" 键）

用法:
  python test_grok45.py                     # 粘贴
  python test_grok45.py keys/token.txt        # 读文件
  python test_grok45.py keys/sso.txt -m grok-4.5 -M "hello"
  python test_grok45.py --keep               # 不恢复原 ~/.grok/auth.json（调试用）

默认消息 "hi"，默认模型 grok-4.5（当前默认模型）。运行过程会备份并临时替换
~/.grok/auth.json，结束后自动恢复。
"""
from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import time

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

GROK = r"C:\Users\G\.grok\bin\grok.exe"
AUTH_FILE = os.path.expanduser(r"~\.grok\auth.json")
BACKUP = os.path.join(
    os.environ.get("TEMP", "."), "grok_test_auth_backup.json"
)
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
ISSUER = "https://auth.x.ai"


def jwt_payload(tok: str) -> dict:
    part = tok.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def build_auth(token: dict) -> dict:
    at = token["access_token"]
    claims = jwt_payload(at)
    sub = claims.get("sub")
    team = claims.get("team_id")
    idt = jwt_payload(token.get("id_token", "")) if token.get("id_token") else {}
    first = idt.get("given_name") or ""
    last = idt.get("family_name") or ""
    email = (
        idt.get("email")
        or token.get("email")
        or claims.get("email")
        or claims.get("preferred_username")
        or idt.get("preferred_username")
        or ""
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        f"{ISSUER}::{CLIENT_ID}": {
            "key": token["access_token"],
            "auth_mode": "oidc",
            "create_time": now.isoformat(),
            "user_id": sub,
            "email": email,
            "first_name": first,
            "last_name": last,
            "principal_type": "User",
            "principal_id": sub,
            "team_id": team,
            "coding_data_retention_opt_out": True,
            "refresh_token": token.get("refresh_token") or "",
            "expires_at": (now + datetime.timedelta(hours=6)).isoformat(),
            "oidc_issuer": ISSUER,
            "oidc_client_id": CLIENT_ID,
        }
    }


def is_json_like(raw: str) -> bool:
    return raw.lstrip().startswith("{")


def parse_raw(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        raise ValueError("空输入")
    if os.path.isfile(raw):
        lines = open(raw, encoding="utf-8", errors="ignore").read().splitlines()
        for ln in lines:
            if ln.strip():
                return parse_raw(ln)
        raise ValueError(f"文件 {raw} 为空")
    if is_json_like(raw):
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("JSON 不是对象")
        for key in data:
            if str(key).startswith(ISSUER):
                return {"auth": data}
        if "access_token" in data:
            return {"auth": build_auth(data)}
        raise ValueError("JSON 里既没有 access_token 也没有 auth 结构")
    if "----" in raw:
        email, sso, sso_rw = (raw.split("----") + [None, None])[:3]
        workspace = r"D:\workspace\34"
        if workspace not in sys.path:
            sys.path.insert(0, workspace)
        from device_flow import device_flow_to_token  # type: ignore

        flow = device_flow_to_token(sso, issue_token=True)
        if not flow.get("ok") or not flow.get("token"):
            raise ValueError(
                f"device flow 换 token 失败: {flow.get('error') or '-'}"
            )
        tok = dict(flow["token"])
        tok.setdefault("email", email or "")
        return {"auth": build_auth(tok), "sso": sso, "email": email}
    raise ValueError("无法识别的输入格式（需要 JSON 行、sso---- 行、auth.json 或文件路径）")


def run_grok(args: list[str], timeout_s: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [GROK, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Grok 4.5 功能测试（粘贴 token/s）")
    ap.add_argument("input", nargs="?", default=None, help="直接内容或文件路径；缺省则等待粘贴")
    ap.add_argument("-M", "--msg", default="hi", help="测试消息（默认 hi）")
    ap.add_argument("-m", "--model", default="grok-4.5", help="模型（默认 grok-4.5）")
    ap.add_argument("--keep", action="store_true", help="测试后不恢复原 auth.json")
    ap.add_argument("--timeout", type=int, default=180, help="等待回复超时秒数（默认 180）")
    args = ap.parse_args()

    raw = args.input or input("[?] 粘贴 token.json 行 / sso 行 / auth.json（或拖入文件路径）> ").strip()
    info = parse_raw(raw)
    auth = info["auth"]

    account_name = ""
    for _v in auth.values():
        if isinstance(_v, dict):
            account_name = (
                _v.get("email")
                or info.get("email")
                or (_v.get("principal_id") or _v.get("user_id") or "")[:12]
                or ""
            )
            break
    if not account_name:
        account_name = "(未知)"

    tmp = os.path.join(os.environ.get("TEMP", "."), "grok_test_auth.json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(auth, f, ensure_ascii=False, indent=2)

    had_old = os.path.isfile(AUTH_FILE)
    if had_old:
        shutil.copy2(AUTH_FILE, BACKUP)

    ok = False
    try:
        shutil.copy2(tmp, AUTH_FILE)
        print(f"[*] 已切换 auth（测试账号: {account_name}）")

        t0 = time.time()
        try:
            r = run_grok(["models"], timeout_s=int(args.timeout))
        except subprocess.TimeoutExpired:
            print("[!] grok models 超时")
            r = None
        if r is not None:
            merged = (r.stdout or "") + (r.stderr or "")
            print("[models] " + merged.strip().replace("\n", " | "))

        cmd = ["-p", args.message, "-m", args.model]
        print(f"[*] 发送: grok -p \"{args.message}\" -m {args.model}")
        try:
            r2 = run_grok(cmd, timeout_s=int(args.timeout))
        except subprocess.TimeoutExpired:
            print(f"[!] 模型 {timeout_s}s 超时（账号可能无权限或风控限制）")
            return 3
        dt = time.time() - t0
        out = (r2.stdout or "") + (r2.stderr or "")
        print(out.strip())
        print(
            f"\n[=] 模型: {args.model} | 耗时: {dt:.1f}s | exit={r2.returncode}"
        )
        ok = r2.returncode == 0 and bool(out.strip().strip(""))
        if ok:
            print("[✓] grok-4.5 功能测试通过（账号可用）")
        else:
            print("[✗] 测试未通过（见上方输出）")
    finally:
        if had_old and not args.keep:
            shutil.copy2(BACKUP, AUTH_FILE)
            print("[*] 已恢复原 auth.json")
        elif args.keep:
            print("[*] --keep：保留测试账号为当前登录（已备份原账号到 " + BACKUP + "）")
        elif not had_old:
            try:
                os.remove(AUTH_FILE)
            except OSError:
                pass
            print("[*] 原 auth.json 不存在，已清理测试写入")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())