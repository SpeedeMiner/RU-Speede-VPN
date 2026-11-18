"""Generate Mihomo, sing-box and Xray/V2Ray from the Happ policy template."""
import argparse
from ipaddress import ip_network
import json

import yaml

from update_happ_profile import ROOT, TEMPLATE, format_json

GEOSITE = "https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release"
GEOIP = "https://raw.githubusercontent.com/SpeedeMiner/Geoip-ru-server/cdn"
MIHOMO_GEOIP = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
REMOTE_DOH_HOST = "dns.google"
DOMESTIC_DOH_HOST = "common.dot.dns.yandex.net"
REMOTE_DOH = f"https://{REMOTE_DOH_HOST}/dns-query"
DOMESTIC_DOH = f"https://{DOMESTIC_DOH_HOST}/dns-query"
STAGES = ("Block", "Proxy", "Direct")
MIHOMO_TARGET = {"Block": "REJECT", "Proxy": "PROXY", "Direct": "DIRECT"}
EXACT_DOMAINS = {"discord-attachments-uploads-prd.storage.googleapis.com"}


def sources(policy, extension):
    result = {}
    for stage in STAGES:
        for entry in policy[stage + "Sites"]:
            kind, name = entry.split(":", 1)
            if kind == "geosite":
                result[f"site-{name}"] = (
                    "domain", f"{GEOSITE}/geosite_{name.upper()}.{extension}"
                )
    result["ip-ru"] = ("ipcidr", f"{GEOIP}/geoip_RU.{extension}")
    return result


def mihomo(policy):
    providers = {
        tag: {
            "type": "http", "behavior": behavior, "format": "mrs",
            "url": url, "path": f"./rule-sets/{tag}.mrs", "interval": 86400,
            "proxy": "DIRECT",
        }
        for tag, (behavior, url) in sources(policy, "mrs").items()
    }
    rules = []
    for stage in STAGES:
        target = MIHOMO_TARGET[stage]
        for entry in policy[stage + "Sites"]:
            kind, name = entry.split(":", 1)
            if kind == "geosite":
                rules.append(f"RULE-SET,site-{name},{target}")
            else:
                match = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN"}[kind]
                rules.append(f"{match},{name},{target}")
        for entry in policy[stage + "Ip"]:
            if entry == "geoip:private":
                rules.append("GEOIP,PRIVATE,DIRECT,no-resolve")
            elif entry == "geoip:ru":
                rules.append(f"RULE-SET,ip-ru,{target}")
            else:
                network = ip_network(entry)
                match = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
                rules.append(f"{match},{network},{target}")
    rules_only = {"rule-providers": providers, "rules": rules + ["MATCH,PROXY"]}
    full = {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
        "mode": "rule", "log-level": "warning", "ipv6": True,
        # Mihomo validates the GeoIP DAT by loading CN before reading PRIVATE.
        "geodata-mode": True, "geox-url": {"geoip": MIHOMO_GEOIP},
        "hosts": policy["DnsHosts"],
        "dns": {
            "enable": True, "enhanced-mode": "redir-host", "use-hosts": True,
            "ipv6": True, "default-nameserver": [policy["DomesticDNSIP"]],
            "proxy-server-nameserver": [DOMESTIC_DOH + "#DIRECT"],
            "nameserver": [REMOTE_DOH + "#PROXY"],
            "direct-nameserver": [DOMESTIC_DOH + "#DIRECT"],
        },
        "proxies": [
            {"name": "LOCAL-SOCKS", "type": "socks5", "server": "127.0.0.1",
             "port": 1081, "udp": True},
        ],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["LOCAL-SOCKS"]}],
        **rules_only,
    }
    return full, rules_only


def sing_box(policy):
    rule_sets = [
        {"type": "remote", "tag": tag, "format": "binary", "url": url,
         "download_detour": "direct", "update_interval": "1d"}
        for tag, (_, url) in sources(policy, "srs").items()
    ]
    rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    dns_rules = [{"domain": list(policy["DnsHosts"]), "action": "route", "server": "hosts"}]
    for stage in STAGES:
        action = {"action": "reject"} if stage == "Block" else {
            "action": "route", "outbound": stage.lower()
        }
        for entry in policy[stage + "Sites"]:
            kind, name = entry.split(":", 1)
            key = {"geosite": "rule_set", "domain": "domain_suffix", "full": "domain"}[kind]
            value = [f"site-{name}" if kind == "geosite" else name]
            rules.append({key: value, **action})
            dns_action = {"action": "reject"} if stage == "Block" else {
                "action": "route", "server": "domestic" if stage == "Direct" else "remote"
            }
            dns_rules.append({key: value, **dns_action})
        if stage == "Block":
            rules.append({"action": "resolve"})
        addresses = policy[stage + "Ip"]
        if addresses == ["geoip:private", "geoip:ru"]:
            rules.extend([{"ip_is_private": True, **action}, {"rule_set": ["ip-ru"], **action}])
        else:
            rules.append({"ip_cidr": [str(ip_network(entry)) for entry in addresses], **action})
    return {
        "dns": {
            "servers": [
                {"type": "hosts", "tag": "hosts", "predefined": {
                    domain: [ip] for domain, ip in policy["DnsHosts"].items()
                }},
                {"type": "hosts", "tag": "bootstrap", "predefined": {
                    REMOTE_DOH_HOST: [policy["RemoteDNSIP"]],
                    DOMESTIC_DOH_HOST: [policy["DomesticDNSIP"]],
                }},
                {"type": "https", "tag": "remote", "server": REMOTE_DOH_HOST,
                 "path": "/dns-query", "detour": "proxy", "domain_resolver": "bootstrap"},
                {"type": "https", "tag": "domestic", "server": DOMESTIC_DOH_HOST,
                 "path": "/dns-query", "domain_resolver": "bootstrap"},
            ],
            "rules": dns_rules, "final": "remote",
        },
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                      "listen_port": 2080}],
        "outbounds": [
            {"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1081},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": rules, "rule_set": rule_sets, "final": "proxy",
                  "default_domain_resolver": "domestic"},
        "experimental": {"cache_file": {"enabled": True}},
    }


def xray(policy):
    # Match the tunneled DNS traffic without entering domain/IP classification again.
    rules = [{"type": "field", "inboundTag": ["speede-dns"], "outboundTag": "proxy"}]
    site_domains = {}
    for stage in STAGES:
        domains = [
            entry.replace("geosite:", "ext:geosite_RU.dat:", 1)
            if entry.startswith("geosite:") else entry
            for entry in policy[stage + "Sites"]
        ]
        addresses = [
            entry.replace("geoip:", "ext:geoip_RU.dat:", 1)
            if entry.startswith("geoip:") else entry
            for entry in policy[stage + "Ip"]
        ]
        action = {"type": "field", "outboundTag": stage.lower()}
        rules.extend([{"domain": domains, **action}, {"ip": addresses, **action}])
        site_domains[stage] = domains
    # A catch-all routing rule would suppress IPIfNonMatch's second pass.
    # The first outbound is the fallback in both Xray and V2Ray.
    return {
        "dns": {
            "tag": "speede-dns",
            "hosts": policy["DnsHosts"],
            "servers": [
                {"address": REMOTE_DOH,
                 "domains": site_domains["Proxy"]},
                {"address": DOMESTIC_DOH.replace("https://", "https+local://", 1),
                 "domains": site_domains["Direct"], "skipFallback": True},
            ],
        },
        "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [
            {"tag": "proxy", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": 1081}]}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": policy["DomainStrategy"], "rules": rules},
    }


def rendered(policy):
    # Happ stores bare hostnames. Restore explicit matching modes only for the other clients.
    policy = {
        **policy,
        **{
            stage + "Sites": [
                entry if entry.startswith("geosite:")
                else f'{"full" if entry in EXACT_DOMAINS else "domain"}:{entry}'
                for entry in policy[stage + "Sites"]
            ]
            for stage in STAGES
        },
    }
    full, rules = mihomo(policy)
    header = "# Сгенерировано scripts/render_profiles.py из шаблона Happ.\n"
    return {
        "mihomo/ru-speede-vpn.yaml": header + yaml.safe_dump(full, sort_keys=False, allow_unicode=True),
        "mihomo/rules-only.yaml": header + yaml.safe_dump(rules, sort_keys=False, allow_unicode=True),
        "sing-box/ru-speede-vpn.json": format_json(sing_box(policy)),
        "xray/ru-speede-vpn.json": format_json(xray(policy)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    policy = json.loads((ROOT / TEMPLATE).read_text(encoding="utf-8"))
    for name, content in rendered(policy).items():
        path = ROOT / name
        if args.check:
            if path.read_bytes() != content.encode("utf-8"):
                parser.exit(1, f"{name} is out of sync. Run scripts/render_profiles.py.\n")
        else:
            path.write_text(content, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
