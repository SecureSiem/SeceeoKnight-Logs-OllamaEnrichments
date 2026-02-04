#!/bin/bash
# Enrich Wazuh USB alerts (rule 111000) using Ollama llama3.2 on Kali

OLLAMA_URL="http://192.168.1.61:11434/api/generate"
MODEL="llama3.2"
OUT_LOG="/var/ossec/logs/seceoknight-enrich.log"

# Read FULL alert JSON from stdin (important: AR input can be multi-line)
INPUT_JSON="$(cat)"

# Debug marker
echo "$(date -Is) usb_ollama_enrich.sh EXECUTED" >> "$OUT_LOG"

# Extract rule id safely (handle execd envelope structure)
RULE_ID="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.id // empty' 2>/dev/null)"

if [ -z "$RULE_ID" ]; then
  echo "$(date -Is) SeceoKnight-ENRICH: ERROR - Could not extract rule.id from input JSON" >> "$OUT_LOG"
  echo "$(date -Is) INPUT_HEAD: $(echo "$INPUT_JSON" | head -c 400)" >> "$OUT_LOG"
  exit 0
fi

# Only enrich USB rule 111000
if [ "$RULE_ID" != "111000" ]; then
  exit 0
fi

AGENT_NAME="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.name // empty' 2>/dev/null)"
AGENT_IP="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.ip // empty' 2>/dev/null)"

DEVICE_NAME="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.eventdata.deviceDescription // empty' 2>/dev/null)"
DEVICE_ID="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.eventdata.deviceId // empty' 2>/dev/null)"
CLASS_NAME="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.eventdata.className // empty' 2>/dev/null)"

EVENT_ID="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.system.eventID // empty' 2>/dev/null)"
EVENT_TIME="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.system.systemTime // empty' 2>/dev/null)"
PROVIDER="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.system.providerName // empty' 2>/dev/null)"
CHANNEL="$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.win.system.channel // empty' 2>/dev/null)"

PROMPT="You are a SOC analyst. Explain this Windows USB alert in plain text only, one short paragraph, no markdown and no new lines. Include what happened, why it matters, and 3 investigation steps. Alert details: rule_id=$RULE_ID agent=$AGENT_NAME ip=$AGENT_IP device_name=$DEVICE_NAME class=$CLASS_NAME event_id=$EVENT_ID provider=$PROVIDER channel=$CHANNEL time=$EVENT_TIME device_id=$DEVICE_ID"

RESP=$(curl -s -X POST "$OLLAMA_URL" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"prompt\":\"$PROMPT\",\"stream\":false,\"options\":{\"temperature\":0.2}}")

TEXT=$(echo "$RESP" | jq -r '.response // empty' 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')

if [ -z "$TEXT" ]; then
  TEXT="None"
fi

echo "SeceoKnight-ENRICH: INFO - base_rule_id=111000 agent=$AGENT_NAME ip=$AGENT_IP device=\"$DEVICE_NAME\" | seceoknight_response: $TEXT" >> "$OUT_LOG"
exit 0
