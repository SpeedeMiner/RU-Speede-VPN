from ipaddress import ip_network
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "happ/ru-speede-vpn.template.json").read_text())
DISCORD = "discord-attachments-uploads-prd.storage.googleapis.com"


def test_mihomo_config_reuses_the_same_order_and_providers():
    part = yaml.safe_load((ROOT / "mihomo/rules-only.yaml").read_text())
    full = yaml.safe_load((ROOT / "mihomo/ru-speede-vpn.yaml").read_text())
    assert all(full[key] == value for key, value in part.items())
    rules = full["rules"]
    assert rules.index("RULE-SET,site-block,REJECT") < rules.index(f"DOMAIN,{DISCORD},PROXY")
    assert rules.index("DOMAIN-SUFFIX,4pda.to,PROXY") < rules.index("RULE-SET,site-ru,DIRECT")
    assert "GEOIP,PRIVATE,DIRECT,no-resolve" in rules
    assert rules[-1] == "MATCH,PROXY"
    assert full["hosts"] == POLICY["DnsHosts"]
    assert full["rule-providers"]["ip-ru"]["behavior"] == "ipcidr"
    for name, provider in full["rule-providers"].items():
        if name.startswith("site-"):
            assert provider["behavior"] == "domain"
            assert provider["url"].endswith(f"/geosite_{name[5:].upper()}.mrs")


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
