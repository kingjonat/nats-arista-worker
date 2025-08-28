import asyncio
import json
import os
import shlex
import tempfile
from pathlib import Path
from typing import Literal, Optional, cast
import subprocess
import yaml
import fnmatch
import difflib

import nats
from pydantic import BaseModel, ValidationError

# Constants
WORKER_NAME = "arista-config-worker"
VERSION = "1.0.0"
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

class Envelope(BaseModel):
    message_id: str
    action: Literal["deploy", "verify", "poll", "dump"]
    payload: dict  # schema varies by action

class PollDevice(BaseModel):
    name: str
    ip: str
    port: Optional[int] = 80
    # optional ad-hoc list of show commands; defaulted if absent
    shows: Optional[list[str]] = None

class PollPayload(BaseModel):
    devices: list[PollDevice]
    

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
            "interfaces_effective": _normalise_interfaces(d.interfaces),
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

# ----------------------------- Response Helper -----------------------------
RESP_SUBJECT = "arista-response"

async def publish_response(nc, *, message_id: str, status: str, rc: int, payload: dict):
    out = {
        "message_id": message_id,
        "action": "response",
        "status": status,     # "success" | "fail"
        "payload": payload,  
    }
    await nc.publish(RESP_SUBJECT, json.dumps(out).encode())


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

async def run_play(payload: Msg, *, dry_run: bool) -> tuple[int, str, str]:
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
        "--diff",
    ]
    if dry_run:
        argv += ["--check"]
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


#------------------------------ POLL FUNCTION ---------------------------------
async def run_poll(poll: PollPayload) -> tuple[int, str, str]:
    """
    Build temp inventory from PollPayload and execute eos_command 'show ... | json'
    for each device. Returns (rc, stdout, stderr) with Ansible JSON callback.
    """
    # Build devices->interfaces empty but we still need creds in inventory
    devices_for_inv = []
    for d in poll.devices:
        devices_for_inv.append(Device(
            name=d.name, ip=d.ip, port=d.port or 80, interfaces=[]
        ))
    inv_path = make_temp_inventory(devices_for_inv)
    limit_pattern = ":".join([d.name for d in poll.devices])

    # default shows if none supplied
    default_shows = [
        "show version",
        "show interfaces status",
    ]

    # Build hostvars mapping for per-host show list
    host_shows = {d.name: (d.shows or default_shows) for d in poll.devices}

    # Write a tiny playbook that uses eos_command with output json
    fd, pb_path = tempfile.mkstemp(suffix=".yml", prefix="poll_", dir=str(tmpdir))
    os.close(fd)
    playbook_text = """\
- name: Poll EOS show commands
  hosts: all
  connection: httpapi
  gather_facts: no
  collections: [arista.eos]
  become: true
  become_method: enable
  vars:
    ansible_network_os: arista.eos.eos
    ansible_httpapi_use_ssl: false
    ansible_httpapi_validate_certs: false
  tasks:
    - name: Build shows list for host
      ansible.builtin.set_fact:
        _shows: "{{ hostvars[inventory_hostname].shows | default(['show version','show interfaces status']) }}"

    - name: Build eos_command payload (list of dicts)
      ansible.builtin.set_fact:
        _cmds: >-
          {{
            _shows
            | map('regex_replace', '^(.*)$', '{\"command\":\"\\1\",\"output\":\"json\"}')
            | map('from_json')
            | list
          }}

    - name: Execute shows (JSON)
      arista.eos.eos_command:
        commands: "{{ _cmds }}"
      register: _poll_out
      when: _cmds | length > 0
"""



    with open(pb_path, "w", encoding="utf-8") as f:
        f.write(playbook_text)

    extra_vars = {}
    # Build hostvars file to attach shows per host in inventory? We can pass in inventory hosts via make_temp_inventory,
    # so attach shows under hosts as a key 'shows'
    # Re-open inventory and add shows into hosts
    with open(inv_path, "r+", encoding="utf-8") as f:
        inv = yaml.safe_load(f) or {}
        hosts = inv.get("all", {}).get("children", {}).get("arista", {}).get("hosts", {})
        for h, lst in host_shows.items():
            if h in hosts:
                hosts[h]["shows"] = lst
        f.seek(0); f.truncate()
        yaml.safe_dump(inv, f, sort_keys=False)

    argv = [
        "ansible-playbook",
        "-i", str(inv_path),
        str(pb_path),
        "--limit", limit_pattern,
        "--extra-vars", json.dumps(extra_vars),
    ]

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

    if not os.environ.get("KEEP_INVENTORY"):
        try: os.remove(inv_path)
        except Exception: pass
    try: os.remove(pb_path)
    except Exception: pass

    return rc, out, err



# ───────────────────────────── NATS subscription ─────────────────────────────

async def main():
    """
    Connect to NATS, subscribe to 'arista-config', and handle messages as they arrive.
    """
    nats_url = os.environ.get("NATS_URL", "nats://127.0.0.1:5050/nats")
    nc = await nats.connect(
    nats_url,
    max_reconnect_attempts=-1,  # forever
    reconnect_time_wait=2,
    ping_interval=20,
    allow_reconnect=True,
)
    print(f"[{WORKER_NAME}] connected to {nats_url}")

    async def handle(msg):
        # 1) Parse JSON
        try:
            raw = json.loads(msg.data.decode())
        except json.JSONDecodeError as e:
            print(f"Bad payload: {e.msg} at line {e.lineno} col {e.colno}")
            return

        # 2) Back-compat: if legacy (no message_id), treat as old Msg
        is_legacy = "message_id" not in raw
        if is_legacy:
            message_id = "legacy-" + os.urandom(4).hex()
            try:
                payload = Msg(**raw)
            except ValidationError as e:
                print("Bad legacy payload:", e)
                return
            dry_run = (payload.action == "dry_run")
            try:
                rc, out, err = await run_play(payload, dry_run=dry_run)
            except Exception as e:
                err_msg = f"worker exception: {type(e).__name__}: {e}"
                print(f"[{WORKER_NAME}] {err_msg}")
                await publish_response(nc, message_id=message_id, status="fail", rc=99,
                                    payload={"error": err_msg})
                return

            stats = parse_ansible_json_stream(out)
            failed = extract_failed_tasks(out)
            diffs = extract_diffs(out)
            print_human_diffs(diffs, dry_run=dry_run, prefix=WORKER_NAME)

            hostnames = [d.name for d in payload.devices] if payload.devices else []
            stats_map: dict[str, dict] = cast(dict[str, dict], stats or {})
            status_ok = (rc in (0, 2)) and all(
                not ((stats_map.get(h) or {}).get("unreachable", 0) or (stats_map.get(h) or {}).get("failures", 0))
                for h in hostnames
            )

            await publish_response(
                nc,
                message_id=message_id,
                status="success" if status_ok else "fail",
                rc=rc,
                payload={
                    "action": payload.action,
                    "stats": stats, "failed_tasks": failed,
                    "diffs": diffs, "stderr_tail": err[-3000:], "stdout_tail": out[-6000:]
                }
            )
            return

        # 3) New envelope path
        try:
            env = Envelope(**raw)
        except ValidationError as e:
            print("Bad envelope:", e)
            return

        if env.action in ("deploy", "verify"):
            # Map envelope.payload -> Msg
            try:
                conf = Msg(**{
                    "action": "dry_run" if env.action == "verify" else "deploy",
                    **env.payload
                })
            except ValidationError as e:
                print("Bad config payload:", e)
                await publish_response(nc, message_id=env.message_id, status="fail", rc=98,
                                    payload={"error": f"payload validation: {e.errors()}"})
                return

            dry_run = (env.action == "verify")
            try:
                rc, out, err = await run_play(conf, dry_run=dry_run)
            except Exception as e:
                err_msg = f"worker exception: {type(e).__name__}: {e}"
                print(f"[{WORKER_NAME}] {err_msg}")
                await publish_response(nc, message_id=env.message_id, status="fail", rc=99,
                                    payload={"error": err_msg})
                return

            stats = parse_ansible_json_stream(out)
            failed = extract_failed_tasks(out)
            diffs = extract_diffs(out)
            print_human_diffs(diffs, dry_run=dry_run, prefix=WORKER_NAME)

            # same success heuristic
            target_hosts = {d.name for d in conf.devices}
            stats_map: dict[str, dict] = cast(dict[str, dict], stats or {})
            bad = {}
            for h in target_hosts:
                s = stats_map.get(h) or {}
                if s.get("unreachable", 0) or s.get("failures", 0):
                    bad[h] = s
            status_ok = (rc in (0, 2)) and not bad

            await publish_response(
                nc,
                message_id=env.message_id,
                status="success" if status_ok else "fail",
                rc=rc,
                payload={
                    "action": env.action,
                    "devices": sorted(list(target_hosts)),
                    "stats": stats, "failed_tasks": failed,
                    "diffs": diffs,
                    "stderr_tail": err[-3000:], "stdout_tail": out[-6000:]
                }
            )
            return

        elif env.action == "poll":
            # Validate poll payload and run
            try:
                poll = PollPayload(**env.payload)
            except ValidationError as e:
                await publish_response(nc, message_id=env.message_id, status="fail", rc=98,
                                    payload={"error": f"poll payload validation: {e.errors()}"})
                return
            try:
                rc, out, err = await run_poll(poll)
            except Exception as e:
                err_msg = f"worker exception: {type(e).__name__}: {e}"
                print(f"[{WORKER_NAME}] {err_msg}")
                await publish_response(nc, message_id=env.message_id, status="fail", rc=99,
                                    payload={"error": err_msg})
                return

            # Try to parse stdout into JSON
            try:
                parsed = json.loads(out)
            except json.JSONDecodeError:
                parsed = out[-6000:]  # fallback to raw string

            # Publish parsed structure instead of escaped string
            await publish_response(
                nc,
                message_id=env.message_id,
                status="success" if rc in (0, 2) else "fail",
                rc=rc,
                payload={
                    "action": "poll",
                    "stdout": parsed,   # structured JSON if possible
                    "stderr_tail": err[-3000:]
                }
            )

            return

        elif env.action == "dump":
            # Not implemented yet
            await publish_response(
                nc,
                message_id=env.message_id,
                status="fail",
                rc=97,
                payload={"error": "dump action not implemented"}
            )
            return

        else:
            await publish_response(
                nc,
                message_id=env.message_id,
                status="fail",
                rc=96,
                payload={"error": f"unknown action '{env.action}'"}
            )



    # Listen for config requests on this subject.
    await nc.subscribe("arista-config", cb=handle)
    print(f"[{WORKER_NAME}] listening on arista-config")

    # Keep the worker alive; NATS callbacks run in the background.
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
