import asyncio
import json
import os
import shlex
import tempfile
from pathlib import Path
from typing import Literal, Optional
import subprocess
import yaml
import fnmatch
import difflib

import nats
from pydantic import BaseModel, ValidationError

# Constants
WORKER_NAME = "arista-config-worker"

# Project paths
ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_DIR = ROOT / "ansible"
tmpdir = ANSIBLE_DIR / ".tmp"
tmpdir.mkdir(exist_ok=True)

# ───────────────────────────── Models (validate incoming payload) ─────────────────────────────

class Interface(BaseModel):
    # One physical/logical interface to configure
    name: str                                # e.g. "Ethernet1"
    mode: Optional[Literal["access", "trunk"] ] = None       # access or trunk
    vlan: Optional[int] | Optional[list[int]] = None                   # single VLAN for access; list for trunk
    description: Optional[str] = None        # optional description
    admin: Literal["up", "down"] = "up"      # admin state
    speed: Optional[str] = None              # optional speed, e.g. "10g" or "auto"

class Device(BaseModel):
    # One switch to target
    name: str                                # switch name to use in Ansible
    ip: str                                  # eAPI management IP/hostname
    port: Optional[int] = 80                 # eAPI TCP port (80/443/8080 etc.)
    interfaces: list[Interface]              # interfaces to apply on this device

class Msg(BaseModel):
    # Whole message from NATS
    action: Literal["deploy", "dry_run"]     # whether to push or just check + diff
    devices: list[Device]                    # one or more devices in a single message
    persist: Optional[bool] = False          # Optional: ask playbook to persist (write memory) after changes
    tags: Optional[list[str]] = None
    skip_tags: Optional[list[str]] = None
    

# ───────────────────────────── Inventory shaping ─────────────────────────────

def make_temp_inventory(devices: list[Device]) -> str:
    vm = _load_vault_map() 
    hosts_obj = {}
    for d in devices:
        creds = _resolve_creds(d.name, vm)
        _validate_creds(creds, d.name)
        hosts_obj[d.name] = {
            "ansible_host": d.ip,
            "ansible_httpapi_port": d.port,
            "ansible_user": creds["username"],
            "ansible_password": creds["password"],
            "ansible_become_password": creds["enable"],
            "interfaces": _normalise_interfaces(d.interfaces),
        }

    group_vars = {
        "ansible_connection": "httpapi",
        "ansible_network_os": "arista.eos.eos",
        "ansible_httpapi_use_ssl": False,
        "ansible_httpapi_validate_certs": False,
    }

    inv = {"all": {"children": {"arista": {"hosts": hosts_obj, "vars": group_vars}}}}
    fd, path = tempfile.mkstemp(suffix=".yml", prefix="inv_", dir=str(tmpdir))
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(inv, f, sort_keys=False)
    os.chmod(path, 0o600)
    return path



# ───────────────────────────── Ansible JSON parsing ─────────────────────────────

def parse_ansible_json_stream(stdout: str) -> dict[str, dict]:
    """
    Parse Ansible 'json' callback output (a single multi-line JSON document).
    Returns stats dict {host: {ok, changed, unreachable, failures, ...}}
    """
    # 1) Try parsing the entire stdout
    try:
        obj = json.loads(stdout)
        if isinstance(obj, dict) and isinstance(obj.get("stats"), dict):
            return obj["stats"]
    except json.JSONDecodeError:
        pass

    # 2) Fallback: extract the biggest {...} block and parse
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            obj = json.loads(stdout[start:end+1])
            if isinstance(obj, dict) and isinstance(obj.get("stats"), dict):
                return obj["stats"]
        except json.JSONDecodeError:
            pass

    return {}  # nothing usable found


def extract_failed_tasks(stdout: str) -> dict[str, list[dict]]:
    """
    From Ansible JSON callback output, return:
      { "host": [ { "task": "name", "msg": "...", "stderr": "...", "module_stdout": "..." }, ... ] }
    """
    failures: dict[str, list[dict]] = {}
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return failures

    for play in obj.get("plays", []):
        for task in play.get("tasks", []):
            tname = task.get("task", {}).get("name")
            for host, res in (task.get("hosts") or {}).items():
                if res.get("failed"):
                    failures.setdefault(host, []).append({
                        "task": tname,
                        "msg": res.get("msg"),
                        "stderr": res.get("stderr"),
                        "module_stdout": res.get("module_stdout"),
                    })
    return failures



# ───────────────────────────── Vault Creds ─────────────────────────────
def _load_vault_map() -> dict:
    """Return dict with vault_arista_creds from ansible-vault."""
    vf = ANSIBLE_DIR / "group_vars" / "all" / "vault.yml"
    proc = subprocess.run(
        ["ansible-vault", "view", str(vf)],
        cwd=str(ANSIBLE_DIR),
        capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Vault decrypt failed: {proc.stderr.strip()}")
    data = yaml.safe_load(proc.stdout) or {}
    vm = data.get("vault_arista_creds") or {}
    if not isinstance(vm, dict):
        raise RuntimeError("vault_arista_creds missing or not a dict")
    return vm

def _resolve_creds(hostname: str, vm: dict) -> dict:
    """Choose creds for hostname: hosts > patterns > defaults. Returns {username,password,enable}."""
    hosts = (vm.get("hosts") or {})
    if hostname in hosts:
        return hosts[hostname]
    pats = (vm.get("patterns") or {})
    for pat, cred in pats.items():
        if fnmatch.fnmatch(hostname, pat):
            return cred
    return vm.get("defaults") or {}

def _validate_creds(c: dict, hostname: str):
    required = ("username", "password", "enable")
    missing = [k for k in required if k not in c or c[k] in (None, "")]
    if missing:
        raise RuntimeError(f"Missing {missing} creds for host '{hostname}' in vault_arista_creds")
    

# ───────────────────────────── Normalisation Helper ─────────────────────────────


def _normalise_interfaces(items: list[Interface]) -> list[dict]:
    out = []
    for i in items:
        d = i.model_dump(exclude_none=True)               # drop None keys
        # normalise admin to 'up'|'down' (accept truthy/bool)
        if 'admin' in d:
            v = str(d['admin']).lower()
            d['admin'] = 'down' if v in ('down', 'false', '0') else 'up'
        # coerce vlan(s) to ints if present
        if 'vlan' in d:
            if isinstance(d['vlan'], list):
                d['vlan'] = [int(x) for x in d['vlan']]
            else:
                d['vlan'] = int(d['vlan'])
        # if mode looks odd, drop it so playbook won’t validate it
        if d.get('mode') not in ('access', 'trunk'):
            d.pop('mode', None)
        out.append(d)
    return out

# ----------------------------- CLI Diff Pretty Parser ----------------------

def _to_lines(x) -> list[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(y) for y in x]
    if isinstance(x, str):
        return x.splitlines()
    # dict/other → pretty JSON
    try:
        return json.dumps(x, indent=2, sort_keys=True).splitlines()
    except Exception:
        return [str(x)]

def _unified(title: str, before, after) -> str:
    a = _to_lines(before)
    b = _to_lines(after)
    return "\n".join(difflib.unified_diff(
        a, b,
        fromfile=f"{title}:before",
        tofile=f"{title}:after",
        lineterm=""
    ))

def extract_diffs(stdout: str) -> dict[str, list[dict]]:
    """
    Returns { host: [ {task, changed, diff, commands, rendered}, ... ] }
    Pulls from Ansible JSON callback structure.
    """
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    out: dict[str, list[dict]] = {}
    for play in obj.get("plays", []):
        for task in play.get("tasks", []):
            tname = (task.get("task") or {}).get("name")
            for host, res in (task.get("hosts") or {}).items():
                changed = bool(res.get("changed"))
                # Common places diffs/intent show up:
                diff = res.get("diff")
                cmds = res.get("commands") or res.get("updates")
                rendered = res.get("rendered")
                if not (changed or diff or cmds or rendered):
                    continue
                out.setdefault(host, []).append({
                    "task": tname,
                    "changed": changed,
                    "diff": diff,
                    "commands": cmds,
                    "rendered": rendered,
                })
    return out

def print_human_diffs(diffs: dict[str, list[dict]], *, dry_run: bool, prefix: str):
    """
    Pretty print per-host changes using unified diffs when possible,
    else fall back to command or rendered previews.
    """
    if not diffs:
        return
    hdr = "DRY-RUN (not applied)" if dry_run else "APPLIED"
    print(f"[{prefix}] ---- CHANGE SUMMARY: {hdr} ----")
    for host, items in diffs.items():
        print(f"[{prefix}] == {host} ==")
        for it in items:
            task = it.get("task") or "<unnamed>"
            print(f"[{prefix}]  task: {task}")
            d = it.get("diff")
            shown = False
            # Try structured before/after
            if isinstance(d, dict):
                if "prepared" in d and d["prepared"]:
                    # Modules sometimes give a "prepared" blob of lines to be sent
                    print("\n".join(f"[{prefix}]    {line}" for line in _to_lines(d["prepared"])[:400]))
                    shown = True
                if ("before" in d) or ("after" in d):
                    print(_unified(task, d.get("before"), d.get("after"))[:4000])
                    shown = True
                if ("before_lines" in d) or ("after_lines" in d):
                    print(_unified(task, d.get("before_lines"), d.get("after_lines"))[:4000])
                    shown = True
            # Fall back to commands/updates
            if not shown and it.get("commands"):
                cmds = it["commands"]
                if not isinstance(cmds, list):
                    cmds = [cmds]
                for c in cmds[:100]:
                    print(f"[{prefix}]    $ {c}")
                shown = True
            # Fall back to rendered blob
            if not shown and it.get("rendered"):
                for line in _to_lines(it["rendered"])[:400]:
                    print(f"[{prefix}]    {line}")
                shown = True
            if not shown:
                print(f"[{prefix}]    (change detected but no diff payload)")

# ───────────────────────────── Playbook runner ─────────────────────────────

def _sanitize_cmd_for_log(argv: list[str]) -> str:
    # hide values after --extra-vars and any arg that looks like creds in inventory (we don’t pass creds via CLI now)
    redacted = []
    skip_next_ev = False
    for a in argv:
        if skip_next_ev:
            redacted.append("<redacted-extra-vars>")
            skip_next_ev = False
            continue
        if a == "--extra-vars":
            redacted.append(a)
            skip_next_ev = True
        else:
            redacted.append(a)
    return " ".join(shlex.quote(x) for x in redacted)

async def run_play(payload: Msg) -> tuple[int, str, str]:
    playbook = ANSIBLE_DIR / "playbooks" / "arista_config.yml"
    inv_path = make_temp_inventory(payload.devices)
    limit_pattern = ":".join([d.name for d in payload.devices])

    persist_flag = bool(getattr(payload, "persist", False))
    apply_l2_flag = bool(getattr(payload, "apply_l2", True))  # optional override
    # tags (validated below)
    tags = getattr(payload, "tags", None) or []
    skip_tags = getattr(payload, "skip_tags", None) or []

    # whitelist tag names to avoid injection/typos
    ALLOWED_TAGS = {"base", "l2", "persist"}
    tags = [t for t in tags if t in ALLOWED_TAGS]
    skip_tags = [t for t in skip_tags if t in ALLOWED_TAGS]

    extra_vars = {"persist": persist_flag, "apply_l2": apply_l2_flag}
    ev_json = json.dumps(extra_vars)

    argv = [
        "ansible-playbook",
        "-i", str(inv_path),
        str(playbook),
        "--limit", limit_pattern,
        "--extra-vars", ev_json,
    ]
    if payload.action == "dry_run":
        argv += ["--check", "--diff"]
    else:
        argv += ["--diff"]
    if tags:
        argv += ["--tags", ",".join(tags)]
    if skip_tags:
        argv += ["--skip-tags", ",".join(skip_tags)]

    print(f"[{WORKER_NAME}] running: {_sanitize_cmd_for_log(argv)}")

    env = os.environ.copy()
    env["ANSIBLE_CONFIG"] = str(ANSIBLE_DIR / "ansible.cfg")
    env["ANSIBLE_STDOUT_CALLBACK"] = "json"
    env["ANSIBLE_LOAD_CALLBACK_PLUGINS"] = "1"

    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(ANSIBLE_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    out_b, err_b = await proc.communicate()
    rc = await proc.wait()
    out, err = out_b.decode(errors="replace"), err_b.decode(errors="replace")

    # Clean up inventory unless debugging
    if not os.environ.get("KEEP_INVENTORY"):
        try: os.remove(inv_path)
        except Exception: pass

    return rc, out, err





# ───────────────────────────── NATS subscription ─────────────────────────────

async def main():
    """
    Connect to NATS, subscribe to 'arista-config', and handle messages as they arrive.
    """
    nats_url = os.environ.get("NATS_URL", "nats://127.0.0.1:4222")
    nc = await nats.connect(nats_url)
    print(f"[{WORKER_NAME}] connected to {nats_url}")

    async def handle(msg):
        # Parse and validate the JSON payload. If it’s not valid, log and drop.
        try:
            payload = Msg(**json.loads(msg.data.decode()))
        except (json.JSONDecodeError, ValidationError) as e:
            print("Bad payload:", e)
            return

        # Run the play against just the devices in this message.
        try:
            rc, out, err = await run_play(payload)
        except Exception as e:
            err_msg = f"worker exception: {type(e).__name__}: {e}"
            print(f"[{WORKER_NAME}] {err_msg}")
            result = {
                "status": "error", "rc": 99, "devices": [d.name for d in payload.devices],
                "stats": None, "missing_from_stats": [d.name for d in payload.devices],
                "failed_tasks": None, "stderr_tail": err_msg, "stdout_tail": ""
            }
            await nc.publish("deploy.results", json.dumps(result).encode())
            return


        stats = parse_ansible_json_stream(out)

        target_hosts = {d.name for d in payload.devices}
        bad_hosts = {}
        missing_from_stats = set()

        if stats:
            for host in target_hosts:
                if host not in stats:
                    missing_from_stats.add(host)
                    continue
                s = stats[host]
                unreachable = s.get("unreachable", 0)
                failures    = s.get("failures", s.get("failed", 0))
                if unreachable or failures:
                    bad_hosts[host] = {"unreachable": unreachable, "failures": failures}
        else:
            # No JSON stats at all — treat as an error, and include a hint
            missing_from_stats = target_hosts

        status_ok = (rc in (0, 2)) and not bad_hosts and not missing_from_stats
        status = "ok" if status_ok else "error"
        failed = extract_failed_tasks(out)

        diffs = extract_diffs(out)
        print_human_diffs(diffs, dry_run=(payload.action == "dry_run"), prefix=WORKER_NAME)


        result = {
            "status": status,
            "rc": rc,
            "devices": sorted(list(target_hosts)),
            "stats": stats or None,
            "missing_from_stats": sorted(list(missing_from_stats)) or None,
            "failed_tasks": failed or None,  
            "stderr_tail": err[-3000:],
            "stdout_tail": out[-6000:]
        }
        await nc.publish("deploy.results", json.dumps(result).encode())

        def _t(s: str | None, n: int = 200) -> str:
            return (s or "").replace("\n", " ")[:n]

        # Console: show why we flagged error
        if status == "ok":
            print(f"[{WORKER_NAME}] rc={rc} status=ok devices={sorted(list(target_hosts))}")
        else:
             print(f"[{WORKER_NAME}] rc={rc} ERROR bad_hosts={bad_hosts or 'none'} missing={sorted(list(missing_from_stats)) or 'none'}")
        if failed:
            for host, items in failed.items():
                for it in items:
                    print(
                        f"[{WORKER_NAME}] FAIL host={host} task='{it.get('task')}' "
                        f"msg='{_t(it.get('msg'))}' "
                        f"stderr='{_t(it.get('stderr'))}' "
                        f"module_stdout='{_t(it.get('module_stdout'))}'"
                    )


    # Listen for config requests on this subject.
    await nc.subscribe("arista-config", cb=handle)
    print(f"[{WORKER_NAME}] listening on arista-config")

    # Keep the worker alive; NATS callbacks run in the background.
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
