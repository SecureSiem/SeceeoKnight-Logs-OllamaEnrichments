#!/usr/bin/env python3
import json
import time
import requests

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
OUT_LOG = "/var/ossec/logs/seceoknight-enrich.log"

OLLAMA_URL = "http://192.168.1.61:11434/api/generate"
MODEL = "llama3.2"

# Add as many rule IDs as you want here:
ENRICH_RULE_IDS = {
    "111000",  # USB device connected
    # "100302",  # example: file modified in Downloads (your custom rule)
    # "XXXXXX",
}

def write_line(line: str) -> None:
    with open(OUT_LOG, "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")

def one_line(s: str) -> str:
    return " ".join((s or "").split())

def build_prompt(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    data = alert.get("data", {}) or {}

    rule_id = str(rule.get("id", ""))
    rule_desc = one_line(rule.get("description", ""))
    groups = rule.get("groups", []) or []
    groups_s = ",".join(groups) if isinstance(groups, list) else str(groups)

    agent_name = agent.get("name", "")
    agent_ip = agent.get("ip", "")
    ts = alert.get("timestamp", "")

    # Optional: rule-specific “hints”
    hint = ""
    if rule_id == "111000":
        hint = "This is typically a Windows external USB device connection event. Focus on device legitimacy, data exfil risk, and policy controls."

    # Keep the prompt short but information-rich.
    prompt = (
        "You are a SOC analyst. Explain this security alert in plain text only, "
        "one short paragraph, no markdown and no new lines. "
        "Include: what happened, why it matters, and 3 investigation steps.\n\n"
        f"Rule: id={rule_id} groups={groups_s} description={rule_desc}\n"
        f"Agent: name={agent_name} ip={agent_ip}\n"
        f"Time: {ts}\n"
        f"Hint: {hint}\n"
        f"Event fields (JSON): {json.dumps(data, ensure_ascii=False)[:1800]}"
    )
    return prompt

def call_ollama(prompt: str) -> str:
    payload = {"model": MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=60)
        if r.status_code == 200:
            txt = (r.json().get("response") or "").replace("\n", " ").strip()
            return txt or "None (empty response)"
        return f"None (Ollama HTTP {r.status_code})"
    except Exception as e:
        return f"None (Ollama error: {e})"

def enrich(alert: dict) -> None:
    rule_id = str((alert.get("rule", {}) or {}).get("id", ""))
    if rule_id not in ENRICH_RULE_IDS:
        return

    agent = alert.get("agent", {}) or {}
    agent_name = agent.get("name", "")
    agent_ip = agent.get("ip", "")

    # Best effort: pull a “device” label if it exists (USB rule)
    device_name = ""
    try:
        device_name = (
            (((alert.get("data") or {}).get("win") or {}).get("eventdata") or {}).get("deviceDescription") or ""
        )
    except Exception:
        device_name = ""

    prompt = build_prompt(alert)
    text = one_line(call_ollama(prompt))

    line = (
        f'SeceoKnight-ENRICH: INFO - base_rule_id={rule_id} agent={agent_name} ip={agent_ip} '
        f'device="{one_line(device_name)}" | seceoknight_response: {text}'
    )
    write_line(line)

def follow(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)  # end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def main():
    write_line(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} wazuh_ollama_enricher STARTED rules={sorted(ENRICH_RULE_IDS)}")
    for line in follow(ALERTS_FILE):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except Exception:
            continue
        enrich(alert)

if __name__ == "__main__":
    main()
