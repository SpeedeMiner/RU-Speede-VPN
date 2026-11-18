import base64
import json
import re

import pytest

from scripts import update_happ_profile as happ

NOW = 1794988800
DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
ALLOWED_SITE = re.compile(
    rf"(?:geosite:[a-z0-9][a-z0-9_-]*|{DOMAIN_LABEL}(?:\.{DOMAIN_LABEL})+)",
    re.IGNORECASE | re.ASCII,
)


@pytest.mark.parametrize("path", [happ.TEMPLATE, happ.PROFILE])
@pytest.mark.parametrize("field", ["DirectSites", "ProxySites", "BlockSites"])
def test_happ_site_rules_are_geosite_tags_or_bare_domains(path, field):
    profile = json.loads((happ.ROOT / path).read_text(encoding="utf-8"))
    for rule in profile[field]:
        assert ALLOWED_SITE.fullmatch(rule), f"{path}: invalid {field} entry {rule!r}"


def test_happ_proxy_domains_are_not_removed():
    profile = json.loads((happ.ROOT / happ.PROFILE).read_text(encoding="utf-8"))
    assert {"discord-attachments-uploads-prd.storage.googleapis.com", "4pda.to"} <= set(
        profile["ProxySites"]
    )


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / happ.TEMPLATE.parent).mkdir()
    template = (happ.ROOT / happ.TEMPLATE).read_text(encoding="utf-8")
    template = template.replace('"RU-Speede-VPN"', '"RU — профиль"')
    (tmp_path / happ.TEMPLATE).write_text(template, encoding="utf-8")
    (tmp_path / happ.README).write_text(
        f"# Test\n\n{happ.BEGIN}\nold block\n{happ.END}\n\nKeep this.\n", encoding="utf-8"
    )
    monkeypatch.setattr(happ.time, "time", lambda: NOW + 0.99)
    return tmp_path


def test_update_all_four_timestamps_and_exact_base64(project):
    assert happ.update(project) == str(NOW)
    raw = (project / happ.PROFILE).read_text(encoding="utf-8")
    profile = json.loads(raw)
    for field in ("Geoipurl", "Geositeurl"):
        assert profile[field].endswith(f"?v={NOW}")
    for field in ("LastUpdated", "lastUpdatedDate"):
        assert profile[field] == str(NOW)
    assert happ.PLACEHOLDER not in raw
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    link = (project / happ.LINK).read_text(encoding="utf-8")
    assert link == "happ://routing/add/" + base64.b64encode(compact).decode("ascii") + "\n"
    assert base64.b64decode(link.rstrip().rsplit("add/", 1)[1], validate=True) == compact
    assert "профиль".encode() in compact
    readme = (project / happ.README).read_text(encoding="utf-8")
    assert f"[Импортировать в Happ]({link.strip()})" in readme
    assert f"Unix `{NOW}`" in readme
    assert readme.startswith("# Test\n\n") and readme.endswith("\n\nKeep this.\n")
    assert happ.update(project, check=True) == str(NOW)


@pytest.mark.parametrize("field", ["Geoipurl", "Geositeurl", "LastUpdated", "lastUpdatedDate"])
def test_check_rejects_each_bad_timestamp(project, field):
    happ.update(project)
    profile_file = project / happ.PROFILE
    profile = json.loads(profile_file.read_text(encoding="utf-8"))
    profile[field] = profile[field].replace(str(NOW), str(NOW - 1))
    changed = happ.format_json(profile)
    profile_file.write_text(changed, encoding="utf-8")
    with pytest.raises(ValueError, match="out of sync"):
        happ.update(project, check=True)
    assert profile_file.read_text(encoding="utf-8") == changed


@pytest.mark.parametrize("file", [happ.LINK, happ.README])
def test_check_rejects_changed_link_or_readme_date(project, file):
    happ.update(project)
    path = project / file
    original = path.read_text(encoding="utf-8")
    change = ("happ://routing/add/AA", f"Unix `{NOW - 1}`")
    old = ("happ://routing/add/", f"Unix `{NOW}`")
    index = int(file == happ.README)
    path.write_text(original.replace(old[index], change[index]), encoding="utf-8")
    with pytest.raises(ValueError, match="out of sync"):
        happ.update(project, check=True)


def test_check_rejects_invalid_published_timestamp_type(project):
    happ.update(project)
    path = project / happ.PROFILE
    content = json.loads(path.read_text(encoding="utf-8"))
    content["LastUpdated"] = NOW
    path.write_text(happ.format_json(content), encoding="utf-8")
    with pytest.raises(ValueError, match="as a string"):
        happ.update(project, check=True)


def test_update_does_not_write_when_markers_are_invalid(project):
    (project / happ.README).write_text(f"{happ.END}\n{happ.BEGIN}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="markers"):
        happ.update(project)
    assert not (project / happ.PROFILE).exists()
