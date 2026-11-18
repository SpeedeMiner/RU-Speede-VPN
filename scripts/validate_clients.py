"""Run genuine client config validators and verify upstream rule assets."""
from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
import gzip
from hashlib import file_digest
import json
import os
from pathlib import Path
import subprocess
import tarfile
from tempfile import TemporaryDirectory
import zipfile

import yaml

from prepare_v2ray_geoip import make_compatible
from render_profiles import GEOIP, GEOSITE
from update_happ_profile import ROOT, format_json

# RFC 7748 Alice public key for the local config checks, not credentials.
TEST_REALITY_PUBLIC_KEY = urlsafe_b64encode(bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)).rstrip(b"=").decode("ascii")


def curl(url, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["curl", "--fail", "--silent", "--show-error", "--location",
         "--retry", "2", "--retry-max-time", "60", "--max-time", "30",
         "--proto", "=https", "--proto-redir", "=https", "--output", str(path), url],
        check=True,
    )


def download_binary(work, name, spec):
    archive = work / (name + ".archive")
    curl(spec["url"], archive)
    with archive.open("rb") as source:
        digest = file_digest(source, "sha256").hexdigest()
    if digest != spec["sha256"]:
        raise ValueError(f"{name} archive SHA-256 mismatch: {digest}")
    binary = work / name
    match spec["format"]:
        case "gzip":
            binary.write_bytes(gzip.decompress(archive.read_bytes()))
        case "tar":
            with tarfile.open(archive, "r:gz") as tar:
                with tar.extractfile(spec["member"]) as executable:
                    binary.write_bytes(executable.read())
        case "zip":
            with zipfile.ZipFile(archive) as zipped:
                binary.write_bytes(zipped.read(spec["member"]))
        case _:
            raise ValueError(f"Unsupported archive format for {name}")
    binary.chmod(0o700)


def run(work, *cmd, env=None, quiet=False):
    if not quiet:
        print(">", *cmd, flush=True)
    subprocess.run(
        [str(arg) for arg in cmd], cwd=work, env=env, check=True, timeout=45,
        stdout=subprocess.DEVNULL if quiet else None,
    )


def main(work):
    lock = json.loads((ROOT / "scripts/client-checksums.json").read_text(encoding="utf-8"))
    mihomo_full = yaml.safe_load((ROOT / "mihomo/ru-speede-vpn.yaml").read_text(encoding="utf-8"))
    mihomo_rules = yaml.safe_load((ROOT / "mihomo/rules-only.yaml").read_text(encoding="utf-8"))
    sing = json.loads((ROOT / "sing-box/ru-speede-vpn.json").read_text(encoding="utf-8"))
    xray = json.loads((ROOT / "xray/ru-speede-vpn.json").read_text(encoding="utf-8"))
    mihomo_home = work / "mihomo-home"
    mihomo_home.mkdir()
    providers = mihomo_full["rule-providers"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = [pool.submit(download_binary, work, name, spec) for name, spec in lock.items()]
        for provider in providers.values():
            jobs.append(pool.submit(curl, provider["url"], mihomo_home / provider["path"]))
        for ruleset in sing["route"]["rule_set"]:
            jobs.append(pool.submit(curl, ruleset["url"], work / f'{ruleset["tag"]}.srs'))
        jobs.extend([
            pool.submit(curl, f"{GEOSITE}/geosite_RU.dat", work / "geosite_RU.dat"),
            pool.submit(curl, f"{GEOIP}/geoip_RU.dat", work / "geoip_RU.dat"),
            pool.submit(curl, mihomo_full["geox-url"]["geoip"], mihomo_home / "GeoIP.dat"),
        ])
        for job in jobs:
            job.result()

    # Fill only the published GER placeholders in a temporary copy.
    ger = next(proxy for proxy in mihomo_full["proxies"] if proxy["name"] == "GER")
    if ger["uuid"] == "uuid":
        ger["uuid"] = "00000000-0000-4000-8000-000000000001"
    reality = ger["reality-opts"]
    if reality["public-key"] == "pubkey":
        reality["public-key"] = TEST_REALITY_PUBLIC_KEY
    full_file = work / "mihomo-full.yaml"
    full_file.write_text(yaml.safe_dump(mihomo_full), encoding="utf-8")

    # Validate that the portable fragment does not require the DNS outbound.
    fragment = {**mihomo_rules, "proxies": [ger],
                "proxy-groups": mihomo_full["proxy-groups"], "geodata-mode": True}
    fragment_file = work / "mihomo-fragment.yaml"
    fragment_file.write_text(yaml.safe_dump(fragment), encoding="utf-8")
    for file in (full_file, fragment_file):
        run(work, work / "mihomo", "-d", mihomo_home, "-f", file, "-t")
    for provider in providers.values():
        path = mihomo_home / provider["path"]
        run(work, work / "mihomo", "convert-ruleset", provider["behavior"], "mrs",
            path, work / f"{path.stem}.txt", quiet=True)
    print(f"Mihomo: decoded {len(providers)} MRS providers", flush=True)

    ger = next(outbound for outbound in sing["outbounds"] if outbound["tag"] == "GER")
    reality = ger["tls"]["reality"]
    if reality["public_key"] == "REPLACE_WITH_PUBLIC_KEY":
        reality["public_key"] = TEST_REALITY_PUBLIC_KEY
    sing_file = work / "sing-box-test.json"
    sing_file.write_text(format_json(sing), encoding="utf-8")
    for name in ("sing-box-1.12", "sing-box-1.13"):
        binary = work / name
        run(work, binary, "check", "-c", sing_file)
        for ruleset in sing["route"]["rule_set"]:
            tag = ruleset["tag"]
            run(work, binary, "rule-set", "decompile", f"{tag}.srs",
                "-o", work / f"{tag}.json", quiet=True)
        print(f"{name}: decoded {len(sing['route']['rule_set'])} binary rule sets", flush=True)

    env = {**os.environ, "XRAY_LOCATION_ASSET": str(work)}
    run(work, work / "xray", "run", "-test", "-config", ROOT / "xray/ru-speede-vpn.json", env=env)
    xray["outbounds"][0] = {"protocol": "blackhole", "tag": "proxy"}
    fixture = work / "xray-test.json"
    fixture.write_text(format_json(xray), encoding="utf-8")
    run(work, work / "xray", "run", "-test", "-config", fixture, env=env)
    v2ray_assets = work / "v2ray-assets"
    v2ray_assets.mkdir()
    (v2ray_assets / "geosite_RU.dat").write_bytes((work / "geosite_RU.dat").read_bytes())
    compatible, removed = make_compatible((work / "geoip_RU.dat").read_bytes())
    (v2ray_assets / "geoip_RU.dat").write_bytes(compatible)
    print(f"V2Ray: removed {removed} incompatible PRIVATE CIDR(s)", flush=True)
    env = {**os.environ, "V2RAY_LOCATION_ASSET": str(v2ray_assets)}
    run(work, work / "v2ray", "test", "-c", ROOT / "xray/ru-speede-vpn.json", env=env)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="ru-speede-vpn-check-") as directory:
        main(Path(directory))
