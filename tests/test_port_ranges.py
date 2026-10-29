"""ACL par plages de ports trop larges (#32) : constat d'extraction et contrôle port_range."""

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from qos_audit.checks import check_port_ranges, run_all
from qos_audit.comware.extract import build_policy
from qos_audit.comware.parser import parse_device
from qos_audit.elastiflow import Window
from qos_audit.models import FlowMatch, QosClass, Severity, wide_port_range
from qos_audit.policy import DEFAULT_THRESHOLDS, load_policy

ROOT = Path(__file__).parent.parent
W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))
RTP = FlowMatch(protocol="udp", dst_ports=(16384, 32767))


def test_wide_port_range() -> None:
    assert wide_port_range(RTP) == (16384, 32767)
    assert wide_port_range(FlowMatch(protocol="udp", src_ports=(10000, 20000), dst_ports=(1, 2000))) == (10000, 20000)
    assert wide_port_range(FlowMatch(protocol="udp", dst_ports=(10000, 11023))) is None  # 1024 ports : toléré
    assert wide_port_range(FlowMatch(protocol="udp", dst_ports=(10000, 11024))) == (10000, 11024)
    assert wide_port_range(replace(RTP, dst_cidr="10.10.5.0/24")) is None
    assert wide_port_range(replace(RTP, src_cidr="10.10.5.0/24")) is None
    assert wide_port_range(FlowMatch(protocol="udp")) is None
    assert wide_port_range(RTP, max_ports=20000) is None
    assert DEFAULT_THRESHOLDS["port_range_max_ports"] == 1024


def test_extraction_flags_wide_range_without_ip() -> None:
    cfg = """
acl advanced 3001
 rule 10 permit udp destination-port range 16384 32767
 rule 20 permit udp destination 10.10.5.0 0.0.0.255 destination-port range 16384 32767
 rule 30 permit udp destination-port range 5060 5061
traffic classifier VOIX operator or
 if-match acl 3001
traffic behavior EF
 remark dscp ef
qos policy QOS-OUT
 classifier VOIX behavior EF
interface GigabitEthernet1/0/49
 qos apply policy QOS-OUT outbound
"""
    _, ext = build_policy([parse_device(cfg, "r1")])
    wide = [i for i in ext.issues if i.code == "acl_port_range_wide"]
    assert len(wide) == 1
    assert wide[0].level == "WARN" and wide[0].subject == "advanced 3001"
    assert "udp ports 16384-32767 (16384 ports) sans IP" in wide[0].message
    assert "IPBX" in wide[0].message


class RangeClient:
    """Client factice : répond selon le filtre de taille et la clé de regroupement demandés."""

    def __init__(self, total: float, big: float, samples: int = 1000, ips: list[dict] | None = None) -> None:
        self.total, self.big, self.samples = total, big, samples
        self.ips = ips if ips is not None else [{"dst_ip": "10.10.5.1", "bytes": 1.0, "samples": 1}]
        self.calls: list[tuple[list[str], dict | None]] = []

    def bytes_by(self, _w, group_by, extra_filter=None, **_kw):
        self.calls.append((group_by, extra_filter))
        text = str(extra_filter)
        if group_by != ["dscp"]:
            return self.ips
        if "> params.t" in text:
            return [{"dscp": 46, "bytes": self.big, "samples": 10}]
        return [{"dscp": 46, "bytes": self.total, "samples": self.samples}]

    def bytes_timeseries(self, *_a, **_kw):
        return []

    def counter_samples(self, *_a, **_kw):
        return []


def _policy():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


def test_voice_range_mostly_voice_is_ok_with_recommendation() -> None:
    ips = [
        {"dst_ip": "10.10.5.2", "bytes": 10.0, "samples": 1},
        {"dst_ip": "10.10.5.1", "bytes": 50.0, "samples": 1},
        {"dst_ip": None, "bytes": 99.0, "samples": 1},
    ]
    c = RangeClient(total=1e6, big=5e4, ips=ips)
    f = check_port_ranges(c, _policy(), W)
    assert [x.subject for x in f] == ["site-a/wan1/ef", "site-a/wan2/ef"]
    assert all(x.check == "port_range" and x.severity == Severity.OK for x in f)
    assert "5.0 % des octets ef en paquets > 300 o" in f[0].message
    assert f[0].evidence["voice_ips"] == ["10.10.5.1", "10.10.5.2"] and f[0].evidence["ip_field"] == "dst_ip"
    assert "restreindre la classe aux IP des IPBX / passerelles (10.10.5.1, 10.10.5.2)" in f[0].message
    # la mesure ne porte que sur les octets marqués de la classe, sur la sortie
    _, flt = c.calls[0]
    assert "'flow.ip.dscp': [46]" in str(flt) and "'network.transport': 'udp'" in str(flt)
    assert f[0].samples == 1000 and f[0].rel_error_pct is not None


def test_voice_range_with_bulk_traffic_warns() -> None:
    f = check_port_ranges(RangeClient(total=1e6, big=4e5, ips=[]), _policy(), W, only_site="site-a")
    assert f[0].severity == Severity.WARN and "40.0 %" in f[0].message
    assert "(aucune IP voix vue)" in f[0].message


def test_voice_range_inconclusive_and_empty_total() -> None:
    f = check_port_ranges(RangeClient(total=1e6, big=0, samples=10), _policy(), W)
    assert f[0].severity == Severity.INCONCLUSIVE and "10 échantillons" in f[0].message
    p = _policy()
    p.thresholds["min_samples"] = 0
    f = check_port_ranges(RangeClient(total=0, big=0, samples=0), p, W)
    assert f[0].severity == Severity.OK and "0.0 %" in f[0].message


def test_source_port_range_uses_source_ip() -> None:
    p = _policy()
    p.classes = [QosClass("ef", (46,), 1, match=(FlowMatch(protocol="udp", src_ports=(16384, 32767)),))]
    c = RangeClient(total=1e6, big=0, ips=[{"src_ip": "10.10.6.10", "bytes": 1.0, "samples": 1}])
    f = check_port_ranges(c, p, W)
    assert f[0].evidence["ip_field"] == "src_ip" and f[0].evidence["voice_ips"] == ["10.10.6.10"]


def test_non_voice_class_flagged_without_measure() -> None:
    p = _policy()
    p.classes = [
        QosClass("d3", (10,), 5, match=(FlowMatch(protocol="tcp", dst_ports=(1024, 65535)),)),
        QosClass("d2", (18,), 4, match=(FlowMatch(protocol="tcp", dst_ports=(443, 443)),)),
    ]
    c = RangeClient(total=1e6, big=0)
    f = check_port_ranges(c, p, W)
    assert len(f) == 1 and f[0].subject == "d3" and f[0].severity == Severity.WARN
    assert "tcp 1024-65535 (64512 ports)" in f[0].message and c.calls == []


def test_run_all_includes_port_range(monkeypatch) -> None:
    from qos_audit import checks

    for name in dir(checks):
        if name.startswith("check_") and name != "check_port_ranges":
            monkeypatch.setattr(checks, name, lambda *_a, **_kw: [])
    f = run_all(RangeClient(total=1e6, big=0), _policy(), W)
    assert any(x.check == "port_range" for x in f)
