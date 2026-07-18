#!/bin/bash

IP="$1"
JAIL="$2"
REASON="$3"
DURATION="$4"
BANTIME="$5" # unused for now
WEBHOOK="$6"

NOW=$(date +%s)
ISO_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

IPAPI_INFO=$(python3 - <<EOF
import json, sys, contextlib
data = None
with contextlib.suppress(Exception):
  data = json.loads('''$(curl -s "http://ip-api.com/json/$IP")''')
if not data or not data.get("status") == "success":
  print("Unknown")
  sys.exit(0)
def getdata(key): return str(data.get(key,"Unknown"))
print("\\\\n".join(f"- **{k}**: {v}" for k, v in {
  "Location": ", ".join([getdata("city"), getdata("regionName"), getdata("country")]),
  "ISP": getdata("isp"), "Org": getdata("org"), "ASN": getdata("as")
}.items()))
EOF
)

PAYLOAD=$(cat <<EOF
{
  "embeds": [
    {
      "title": "User Banned",
      "color": 16711680,
      "timestamp": "$ISO_TIMESTAMP",
      "fields": [
        {
          "name": "IP",
          "value": "$IP",
          "inline": true
        },
        {
          "name": "Reason",
          "value": "$REASON",
          "inline": true
        },
        {
          "name": "Duration",
          "value": "$DURATION",
          "inline": true
        },
        {
          "name": "Jail",
          "value": "$JAIL",
          "inline": true
        },
        {
          "name": "Server",
          "value": "$(hostname)",
          "inline": true
        },
        {
          "name": "IP Info",
          "value": "$IPAPI_INFO",
          "inline": false
        }
      ]
    }
  ]
}
EOF
)

curl -fsSH "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK"
