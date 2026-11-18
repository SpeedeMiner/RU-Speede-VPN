from ipaddress import ip_network
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "happ/ru-speede-vpn.template.json").read_text())
DISCORD = "discord-attachments-uploads-prd.storage.googleapis.com"


def load_mihomo(name="ru-speede-vpn.yaml"):
    return yaml.safe_load((ROOT / "mihomo" / name).read_text(encoding="utf-8"))


def test_mihomo_config_reuses_the_same_order_and_providers():
    part = load_mihomo("rules-only.yaml")
    full = load_mihomo()
    dns_rule, *rules = full["rules"]
    assert dns_rule == "DST-PORT,53,DNS-OUT"
    assert part == {"rule-providers": full["rule-providers"], "rules": rules}
    assert rules.index("RULE-SET,site-block,REJECT") < rules.index(f"DOMAIN,{DISCORD},PROXY")
    assert rules.index("DOMAIN-SUFFIX,4pda.to,PROXY") < rules.index("RULE-SET,site-ru,DIRECT")
    assert "GEOIP,PRIVATE,DIRECT,no-resolve" in rules
    assert rules[-2] == "RULE-SET,ip-ru,DIRECT,no-resolve"
    assert rules[-1] == "MATCH,PROXY"
    assert full["hosts"] == POLICY["DnsHosts"]
    assert full["rule-providers"]["ip-ru"]["behavior"] == "ipcidr"
    for name, provider in full["rule-providers"].items():
        assert provider["proxy"] == "PROXY"
        if name.startswith("site-"):
            assert provider["behavior"] == "domain"
            assert provider["url"].endswith(f"/geosite_{name[5:].upper()}.mrs")


def test_mihomo_lan_network_and_process_settings():
    config = load_mihomo()
    assert config["bind-address"] == "*" and config["find-process-mode"] == "always"
    assert all(config[key] is True for key in (
        "allow-lan", "tcp-concurrent", "enable-process", "unified-delay"
    ))
    assert config["lan-allowed-ips"] == [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
    ]


def test_mihomo_dns_sniffer_and_tun():
    config = load_mihomo()
    dns = config["dns"]
    assert dns["listen"] == "0.0.0.0:53" and dns["cache-algorithm"] == "arc"
    assert all(dns[key] is True for key in ("enable", "respect-rules", "use-system-hosts"))
    assert dns["proxy-server-nameserver"]
    assert config["sniffer"] == {
        "enable": True, "force-dns-mapping": True, "parse-pure-ip": True,
        "override-destination": False,
        "sniff": {
            "HTTP": {"ports": [80, "8080-8880"]},
            "TLS": {"ports": [443, 8443]},
            "QUIC": {"ports": [443, 8443]},
        },
    }
    assert config["tun"] == {
        "enable": True, "stack": "mips", "auto-route": True,
        "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
        "strict-route": True,
    }


def test_mihomo_dns_out_and_reality_template():
    config = load_mihomo()
    assert config["proxies"] == [
        {"name": "DNS-OUT", "type": "dns"},
        {
            "name": "GER", "type": "vless", "server": "server.example.com",
            "port": 443, "network": "tcp", "udp": True, "uuid": "uuid",
            "packet-encoding": "xudp", "tls": True, "servername": "www.example.com",
            "reality-opts": {"public-key": "pubkey", "short-id": "", "support-x25519mlkem768": True},
            "client-fingerprint": "chrome",
        },
    ]
    assert config["proxy-groups"] == [{
        "name": "PROXY", "type": "select", "url": "https://www.gstatic.com/generate_204",
        "interval": 300, "timeout": 5000, "max-failed-times": 3, "proxies": ["GER"],
    }]


def load_sing_box():
    return json.loads((ROOT / "sing-box/ru-speede-vpn.json").read_text(encoding="utf-8"))


def sing_site_tags(stage):
    return [entry.replace("geosite:", "site-", 1) for entry in POLICY[stage + "Sites"]
            if entry.startswith("geosite:")]


def test_sing_box_order_and_rule_set_downloads():
    route = load_sing_box()["route"]
    assert route["final"] == "PROXY"
    assert route["auto_detect_interface"] is True
    assert route["default_domain_resolver"] == "dns-direct"
    rule_sets = route["rule_set"]
    assert len(rule_sets) == 19
    expected_tags = {
        *sing_site_tags("Block"), *sing_site_tags("Proxy"), *sing_site_tags("Direct"),
        "ip-private", "ip-ru",
    }
    assert {item["tag"] for item in rule_sets} == expected_tags
    for item in rule_sets:
        assert (item["type"], item["format"], item["download_detour"], item["update_interval"]) == (
            "remote", "binary", "PROXY", "1d"
        )
        tag = item["tag"]
        if tag.startswith("site-"):
            asset = f"Geosite-ru-light/release/geosite_{tag[5:].upper()}.srs"
        else:
            asset = f"Geoip-ru-server/cdn/geoip_{tag[3:].upper()}.srs"
        assert item["url"] == f"https://raw.githubusercontent.com/SpeedeMiner/{asset}"
    block_ips = [str(ip_network(ip)) for ip in POLICY["BlockIp"]]
    assert len(block_ips) == 7
    assert route["rules"] == [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "DIRECT"},
        {"rule_set": sing_site_tags("Block"), "action": "reject"},
        {"ip_cidr": block_ips, "action": "reject"},
        {"rule_set": sing_site_tags("Proxy"), "outbound": "PROXY"},
        {"domain": [DISCORD], "domain_suffix": ["4pda.to"], "outbound": "PROXY"},
        {"ip_cidr": POLICY["ProxyIp"], "outbound": "PROXY"},
        {"rule_set": sing_site_tags("Direct"), "outbound": "DIRECT"},
        {"domain_suffix": ["ru", "kz", "su", "by", "xn--p1ai"], "outbound": "DIRECT"},
        {"rule_set": ["ip-private", "ip-ru"], "outbound": "DIRECT"},
    ]


def test_sing_box_https_dns_hosts_and_priority():
    dns = load_sing_box()["dns"]
    assert (dns["final"], dns["strategy"], dns["independent_cache"]) == (
        "dns-proxy", "prefer_ipv4", True
    )
    assert dns["servers"] == [
        {"type": "https", "tag": "dns-proxy", "server": "8.8.8.8", "server_port": 443,
         "path": "/dns-query", "detour": "PROXY",
         "tls": {"enabled": True, "server_name": "dns.google"}},
        {"type": "https", "tag": "dns-direct", "server": "77.88.8.8", "server_port": 443,
         "path": "/dns-query", "tls": {"enabled": True, "server_name": "common.dot.dns.yandex.net"}},
        {"type": "hosts", "tag": "dns-hosts", "predefined": POLICY["DnsHosts"]},
    ]
    assert dns["rules"] == [
        {"domain": list(POLICY["DnsHosts"]), "action": "route", "server": "dns-hosts"},
        {"rule_set": sing_site_tags("Block"), "action": "reject"},
        {"rule_set": sing_site_tags("Direct"), "action": "route", "server": "dns-direct"},
        {"domain_suffix": ["ru", "kz", "su", "by", "xn--p1ai"], "action": "route", "server": "dns-direct"},
    ]


def test_sing_box_tun_reality_selector_and_cache():
    config = load_sing_box()
    assert config["inbounds"] == [
        {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
         "mtu": 9000, "auto_route": True, "strict_route": True, "stack": "mixed"},
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
    ]
    assert config["outbounds"] == [
        {"type": "selector", "tag": "PROXY", "outbounds": ["GER", "AUTO"],
         "default": "GER", "interrupt_exist_connections": True},
        {"type": "urltest", "tag": "AUTO", "outbounds": ["GER"],
         "url": "https://www.gstatic.com/generate_204", "interval": "5m", "tolerance": 50},
        {"type": "vless", "tag": "GER", "server": "server.example.com", "server_port": 443,
         "uuid": "00000000-0000-0000-0000-000000000000", "flow": "xtls-rprx-vision",
         "packet_encoding": "xudp", "tls": {
             "enabled": True, "server_name": "www.example.com",
             "utls": {"enabled": True, "fingerprint": "chrome"},
             "reality": {"enabled": True, "public_key": "REPLACE_WITH_PUBLIC_KEY", "short_id": ""},
         }},
        {"type": "direct", "tag": "DIRECT"},
    ]
    assert config["experimental"]["cache_file"] == {"enabled": True, "store_rdrc": True}


def test_xray_drives_ip_fallback_without_a_catch_all():
    config = json.loads((ROOT / "xray/ru-speede-vpn.json").read_text())
    assert config["dns"]["hosts"] == POLICY["DnsHosts"]
    assert config["outbounds"][0]["tag"] == "proxy"
    route = config["routing"]
    assert route["domainStrategy"] == "IPIfNonMatch"
    dns_rule, *rules = route["rules"]
    assert dns_rule["inboundTag"] == [config["dns"]["tag"]]
    assert dns_rule["outboundTag"] == "proxy"
    assert [rule["outboundTag"] for rule in rules] == [
        "block", "block", "proxy", "proxy", "direct", "direct"
    ]
    assert rules[1]["ip"] == POLICY["BlockIp"]
    assert rules[3]["ip"] == POLICY["ProxyIp"]
    assert f"full:{DISCORD}" in rules[2]["domain"]
    assert "domain:4pda.to" in rules[2]["domain"]
    assert rules[-1]["ip"] == ["ext:geoip_RU.dat:private", "ext:geoip_RU.dat:ru"]
