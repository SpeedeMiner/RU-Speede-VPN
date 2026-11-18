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


def test_sing_box_dns_hosts_priority_and_rule_set_downloads():
    config = json.loads((ROOT / "sing-box/ru-speede-vpn.json").read_text())
    assert config["dns"]["servers"][0]["predefined"] == {
        host: [ip] for host, ip in POLICY["DnsHosts"].items()
    }
    route = config["route"]
    assert route["final"] == "proxy"
    assert route["default_domain_resolver"] == "domestic"
    for item in route["rule_set"]:
        assert (item["format"], item["download_detour"], item["update_interval"]) == (
            "binary", "direct", "1d"
        )
    rules = route["rules"]
    assert rules.index({"ip_cidr": [str(ip_network(ip)) for ip in POLICY["BlockIp"]],
                        "action": "reject"}) < rules.index(
        {"domain": [DISCORD], "action": "route", "outbound": "proxy"}
    )
    assert {"ip_cidr": POLICY["ProxyIp"], "action": "route", "outbound": "proxy"} in rules
    assert {"domain_suffix": ["4pda.to"], "action": "route", "outbound": "proxy"} in rules
    assert rules[-1] == {"rule_set": ["ip-ru"], "action": "route", "outbound": "direct"}


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
