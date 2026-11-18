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
            "proxy": "PROXY",
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
                rules.append(f"RULE-SET,ip-ru,{target},no-resolve")
            else:
                network = ip_network(entry)
                match = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
                rules.append(f"{match},{network},{target}")
    rules_only = {"rule-providers": providers, "rules": rules + ["MATCH,PROXY"]}
    full = {
        "mixed-port": 7890, "allow-lan": True, "bind-address": "*",
        "lan-allowed-ips": [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "::1/128", "fc00::/7",
        ],
        "tcp-concurrent": True, "enable-process": True,
        "find-process-mode": "always", "unified-delay": True,
        "mode": "rule", "log-level": "warning", "ipv6": True,
        # Mihomo validates the GeoIP DAT by loading CN before reading PRIVATE.
        "geodata-mode": True, "geox-url": {"geoip": MIHOMO_GEOIP},
        "hosts": policy["DnsHosts"],
        "dns": {
            "enable": True, "enhanced-mode": "redir-host", "use-hosts": True,
            "use-system-hosts": True, "listen": "0.0.0.0:53",
            "respect-rules": True, "cache-algorithm": "arc",
            "ipv6": True, "default-nameserver": [policy["DomesticDNSIP"]],
            "proxy-server-nameserver": [DOMESTIC_DOH + "#DIRECT"],
            "nameserver": [REMOTE_DOH + "#PROXY"],
            "direct-nameserver": [DOMESTIC_DOH + "#DIRECT"],
        },
        "sniffer": {
            "enable": True, "force-dns-mapping": True, "parse-pure-ip": True,
            "override-destination": False,
            "sniff": {
                "HTTP": {"ports": [80, "8080-8880"]},
                "TLS": {"ports": [443, 8443]},
                "QUIC": {"ports": [443, 8443]},
            },
        },
        "tun": {
            "enable": True, "stack": "mips", "auto-route": True,
            "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
            "strict-route": True,
        },
        "proxies": [
            {"name": "DNS-OUT", "type": "dns"},
            {
                "name": "GER", "type": "vless", "server": "server.example.com",
                "port": 443, "network": "tcp", "udp": True, "uuid": "uuid",
                "packet-encoding": "xudp", "tls": True, "servername": "www.example.com",
                "reality-opts": {
                    "public-key": "pubkey", "short-id": "", "support-x25519mlkem768": True,
                },
                "client-fingerprint": "chrome",
            },
        ],
        "proxy-groups": [{
            "name": "PROXY", "type": "select", "url": "https://www.gstatic.com/generate_204",
            "interval": 300, "timeout": 5000, "max-failed-times": 3, "proxies": ["GER"],
        }],
        "rule-providers": providers,
        "rules": ["DST-PORT,53,DNS-OUT", *rules_only["rules"]],
    }
    return full, rules_only


def sing_site_matches(entries):
    tags, domains = [], {}
    for entry in entries:
        kind, name = entry.split(":", 1)
        if kind == "geosite":
            tags.append(f"site-{name}")
        else:
            key = {"domain": "domain_suffix", "full": "domain"}[kind]
            domains.setdefault(key, []).append(name)
    if tags:
        yield {"rule_set": tags}
    if domains:
        yield domains


def sing_box(policy):
    urls = {tag: url for tag, (_, url) in sources(policy, "srs").items()}
    urls["ip-private"] = f"{GEOIP}/geoip_PRIVATE.srs"
    rule_sets = [
        {"type": "remote", "tag": tag, "format": "binary", "url": url,
         "download_detour": "PROXY", "update_interval": "1d"}
        for tag, url in urls.items()
    ]
    blocks, proxies, directs = (
        list(sing_site_matches(policy[f"{stage}Sites"])) for stage in STAGES
    )
    direct_suffixes = {"domain_suffix": ["ru", "kz", "su", "by", "xn--p1ai"]}
    dns_rules = [
        {"domain": list(policy["DnsHosts"]), "action": "route", "server": "dns-hosts"},
        *({**match, "action": "reject"} for match in blocks),
        *({**match, "action": "route", "server": "dns-direct"}
          for match in [*directs, direct_suffixes]),
    ]
    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "DIRECT"},
        *({**match, "action": "reject"} for match in blocks),
        {"ip_cidr": [str(ip_network(ip)) for ip in policy["BlockIp"]], "action": "reject"},
        *({**match, "outbound": "PROXY"} for match in proxies),
        {"ip_cidr": [str(ip_network(ip)) for ip in policy["ProxyIp"]], "outbound": "PROXY"},
        *({**match, "outbound": "DIRECT"} for match in directs),
        {**direct_suffixes, "outbound": "DIRECT"},
        {"rule_set": ["ip-private", "ip-ru"], "outbound": "DIRECT"},
    ]
    return {
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-proxy", "server": policy["RemoteDNSIP"],
                 "server_port": 443, "path": "/dns-query", "detour": "PROXY",
                 "tls": {"enabled": True, "server_name": REMOTE_DOH_HOST}},
                {"type": "https", "tag": "dns-direct", "server": policy["DomesticDNSIP"],
                 "server_port": 443, "path": "/dns-query",
                 "tls": {"enabled": True, "server_name": DOMESTIC_DOH_HOST}},
                {"type": "hosts", "tag": "dns-hosts", "predefined": policy["DnsHosts"]},
            ],
            "rules": dns_rules, "final": "dns-proxy",
            "strategy": "prefer_ipv4", "independent_cache": True,
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in",
             "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
             "mtu": 9000, "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
        ],
        "outbounds": [
            {"type": "selector", "tag": "PROXY", "outbounds": ["GER", "AUTO"],
             "default": "GER", "interrupt_exist_connections": True},
            {"type": "urltest", "tag": "AUTO", "outbounds": ["GER"],
             "url": "https://www.gstatic.com/generate_204", "interval": "5m", "tolerance": 50},
            {
                "type": "vless", "tag": "GER", "server": "server.example.com", "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000", "flow": "xtls-rprx-vision",
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True, "server_name": "www.example.com",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": "REPLACE_WITH_PUBLIC_KEY",
                                "short_id": ""},
                },
            },
            {"type": "direct", "tag": "DIRECT"},
        ],
        "route": {"rules": rules, "rule_set": rule_sets, "final": "PROXY",
                  "auto_detect_interface": True, "default_domain_resolver": "dns-direct"},
        "experimental": {"cache_file": {"enabled": True, "store_rdrc": True}},
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
