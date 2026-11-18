"""Render the Happ profile, share link and the managed README block."""
import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = Path("happ/ru-speede-vpn.template.json")
PROFILE = Path("happ/ru-speede-vpn.json")
LINK = Path("happ/happ-routing-link.txt")
README = Path("README.md")
BEGIN = "<!-- BEGIN_HAPP_LINK -->"
END = "<!-- END_HAPP_LINK -->"
PLACEHOLDER = "{{TIMESTAMP}}"
URL_FIELDS = ("Geoipurl", "Geositeurl")
DATE_FIELDS = ("LastUpdated", "lastUpdatedDate")


def format_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_profile(template, timestamp):
    data = json.loads(template)
    for name in URL_FIELDS:
        if not data.get(name, "").endswith("?v=" + PLACEHOLDER):
            raise ValueError(f"Missing ?v={PLACEHOLDER} in {name}")
        data[name] = data[name].removesuffix(PLACEHOLDER) + timestamp
    for name in DATE_FIELDS:
        if data.get(name) != PLACEHOLDER:
            raise ValueError(f"Missing {PLACEHOLDER} in {name}")
        data[name] = timestamp
    if PLACEHOLDER in json.dumps(data):
        raise ValueError("Unexpected timestamp placeholder outside the four fields")
    return data


def render_link(profile):
    payload = json.dumps(profile, separators=(",", ":"), ensure_ascii=False)
    return "happ://routing/add/" + base64.b64encode(payload.encode("utf-8")).decode("ascii")


def replace_readme_block(readme, link, timestamp):
    if readme.count(BEGIN) != 1 or readme.count(END) != 1 or readme.index(BEGIN) >= readme.index(END):
        raise ValueError("README must have one correctly ordered pair of Happ markers")
    updated = datetime.fromtimestamp(int(timestamp), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    block = (
        f"{BEGIN}\n"
        f"[Импортировать в Happ]({link}) · Обновлено {updated} · Unix `{timestamp}`\n\n"
        "Если GitHub не открывает ссылку, скопируйте её из "
        "[happ-routing-link.txt](happ/happ-routing-link.txt) и откройте на устройстве с Happ.\n"
        f"{END}"
    )
    return readme[:readme.index(BEGIN)] + block + readme[readme.index(END) + len(END):]


def update(root=ROOT, *, check=False):
    template = (root / TEMPLATE).read_text(encoding="utf-8")
    readme = (root / README).read_text(encoding="utf-8")
    if check:
        published = json.loads((root / PROFILE).read_text(encoding="utf-8"))
        timestamp = published.get("LastUpdated")
        if not isinstance(timestamp, str) or not re.fullmatch(r"0|[1-9][0-9]{0,11}", timestamp):
            raise ValueError("LastUpdated must be a Unix timestamp in seconds, as a string")
    else:
        timestamp = str(int(time.time()))
    profile = render_profile(template, timestamp)
    link = render_link(profile)
    expected = {
        PROFILE: format_json(profile),
        LINK: link + "\n",
        README: replace_readme_block(readme, link, timestamp),
    }
    if check:
        for path, content in expected.items():
            if (root / path).read_bytes() != content.encode("utf-8"):
                raise ValueError(f"{path} is out of sync. Run scripts/update_happ_profile.py.")
    else:
        for path, content in expected.items():
            (root / path).write_text(content, encoding="utf-8", newline="\n")
    return timestamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without modifying files")
    args = parser.parse_args()
    try:
        print(f"Happ timestamp {update(check=args.check)}")
    except (OSError, ValueError, OverflowError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
