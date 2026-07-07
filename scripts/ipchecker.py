# i really overengineered this script because i was bored
# and idk if it even works that well but it should be fineee

import json
import os
import re
import sys
from datetime import UTC, datetime
from enum import Enum
from typing import TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOOK = "https://discord.com/api/webhooks/1522639550109978715/0Tzg3PONa9Hz0bVHUeePbltUapahjssQ1yKYdWPnTklAMqvpqFlbUvDWXoi69LJsjI58"

IPV4 = "159.195.16.172"
IPV6 = "2a0a:4cc0:101:1316:88c2:38ff:fecd:7f23"

PING = os.getenv("PING", '-# *No environment variable for warnings/error pings was defined. Set PING="<@YOUR-DISCORD-USERID>" to enable this feature.')  # noqa: E501


class Color:
    teal = 0x1ABC9C
    dark_teal = 0x11806A
    brand_green = 0x57F287
    green = 0x2ECC71
    dark_green = 0x1F8B4C
    blue = 0x3498DB
    dark_blue = 0x206694
    purple = 0x9B59B6
    dark_purple = 0x71368A
    magenta = 0xE91E63
    dark_magenta = 0xAD1457
    gold = 0xF1C40F
    dark_gold = 0xC27C0E
    orange = 0xE67E22
    dark_orange = 0xA84300
    brand_red = 0xED4245
    red = 0xE74C3C
    dark_red = 0x992D22
    lighter_grey = 0x95A5A6
    dark_grey = 0x607D8B
    light_grey = 0x979C9F
    darker_grey = 0x546E7A
    blurple = 0x5865F2
    greyple = 0x99AAB5
    fuchsia = 0xEB459E
    yellow = 0xFEE75C
    pink = 0xEB459F


class LevelColorEnum(Enum):
    INFO = Color.green
    WARNING = Color.orange
    ERROR = Color.red


LevelHierarchy = [LevelColorEnum.ERROR, LevelColorEnum.WARNING, LevelColorEnum.INFO]
PingWorthyLevels = [LevelColorEnum.ERROR, LevelColorEnum.WARNING]


class Line(TypedDict):
    level: LevelColorEnum
    message: str


Lines = list[Line]


def get_status_color(lines: Lines) -> int:
    for level in LevelHierarchy:
        if any(line["level"] == level for line in lines):
            return level.value
            break
    else:
        return Color.lighter_grey


def fetch_ip(url: str) -> str | None:
    try:
        with urlopen(url, timeout=15) as response:  # noqa: S310
            body = response.read().decode("utf-8").strip()
            body = re.sub(r"\s+", "", body)
            if body:
                return body
            return None
    except (URLError, HTTPError, OSError):
        return None


def is_ipv6(address: str) -> bool:
    return ":" in address


def send_discord(lines: Lines, title: str = "VPS IP Checker") -> None:
    description = "\n".join(line["message"] for line in lines)
    color = get_status_color(lines)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    class BasicDiscordPayloadType(TypedDict):
        embeds: list[dict]
        content: str

    payload: BasicDiscordPayloadType = {
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "timestamp": timestamp,
            "footer": {"text": "IP Checker"},
        }],
        "content": "",
    }

    if any(line["level"] in PingWorthyLevels for line in lines):
        payload["content"] = PING

    try:
        data = json.dumps(payload).encode("utf-8")
        response = urlopen(
            Request(
                HOOK,
                data=data,
                headers={"Content-Type": "application/json"},
            ),
            timeout=15,
        )
        if response.status != 200:  # noqa: PLR2004
            print(f"Warning: Discord webhook returned status {response.status}", file=sys.stderr)
    except (URLError, HTTPError, OSError) as e:
        print(f"Warning: Failed to send Discord webhook: {e}", file=sys.stderr)


def main() -> None:  # noqa: PLR0912
    errors = []

    ipv4 = fetch_ip("https://ipv4.myip.wtf/text")
    if not ipv4:
        errors.append("Failed to fetch IPv4")

    ipv6 = fetch_ip("https://myip.wtf/text")
    if not ipv6:
        errors.append("Failed to fetch IPv6")

    no_ipv6_detected = False
    if ipv4 and ipv6 and (ipv4 == ipv6 or not is_ipv6(ipv6)):
        no_ipv6_detected = True
        errors.append("No IPv6 connectivity detected")

    if errors:
        error_desc = "\n".join(f"- {e}" for e in errors)
        send_discord([{
            "level": LevelColorEnum.ERROR,
            "message": error_desc,
        }], "IP Check Error")

    lines: Lines = []

    if ipv4:
        if ipv4 == IPV4:
            lines.append(Line(
                level=LevelColorEnum.INFO,
                message=f"✅ IPv4 matches: `{ipv4}`",
            ))
        else:
            lines.append(Line(
                level=LevelColorEnum.ERROR,
                message=f"❌ IPv4 mismatch — expected `{IPV4}`, got `{ipv4}`",
            ))
    else:
        lines.append(Line(
            level=LevelColorEnum.WARNING,
            message="⚠ IPv4 unavailable (fetch failed)",
        ))

    if ipv6 and not no_ipv6_detected:
        if ipv6 == IPV6:
            lines.append(Line(
                level=LevelColorEnum.INFO,
                message=f"✅ IPv6 matches: `{ipv6}`",
            ))
        else:
            lines.append(Line(
                level=LevelColorEnum.ERROR,
                message=f"❌ IPv6 mismatch — expected `{IPV6}`, got `{ipv6}`",
            ))
    elif no_ipv6_detected:
        lines.append(Line(
            level=LevelColorEnum.WARNING,
            message="⚠ IPv6 not detected (endpoint fell back to IPv4)",
        ))
    else:
        lines.append(Line(
            level=LevelColorEnum.WARNING,
            message="⚠ IPv6 unavailable (fetch failed)",
        ))

    send_discord(lines)


if __name__ == "__main__":
    main()
