from pathlib import Path

from azguardian.collector import collect_from_file, collect_flow_logs_from_file
from azguardian.rule_engine import (
    run_engine,
    check_overly_broad_service_tags,
    check_missing_asgs,
    check_databricks_subnet_nsg,
    check_nsg_flow_logs_to_log_analytics,
    check_vnet_flow_logs_to_log_analytics,
    check_alert_create_update_nsg,
    check_alert_delete_nsg,
    check_network_watcher_enabled,
    check_network_security_perimeter,
    check_ddos_protection,
    check_nsg_flow_log_retention,
    check_vnet_flow_log_retention,
)

FIXTURES_DIR = Path(__file__).parents[3] / "test-data"


def collect(fixture_name: str):
    return collect_from_file(FIXTURES_DIR / fixture_name)


def collect_flow_logs(fixture_name: str):
    return collect_flow_logs_from_file(FIXTURES_DIR / fixture_name)


def test_violation_nsg_has_rdp_fail():
    nsgs = collect("violation-nsg.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.1" for r in fails)


def test_violation_nsg_has_ssh_fail():
    nsgs = collect("violation-nsg.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.2" for r in fails)


def test_violation_nsg_has_http_fail():
    nsgs = collect("violation-nsg.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.4" for r in fails)


def test_violation_nsg_has_https_fail():
    nsgs = collect("violation-nsg.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.4" for r in fails)


def test_clean_nsg_no_internet_exposure():
    nsgs = collect("clean-nsg.json")
    results = run_engine(nsgs)
    internet_fails = [r for r in results if r.status == "fail" and r.control_id in {"7.1", "7.2", "7.3", "7.4"}]
    assert len(internet_fails) == 0


def test_any_any_flagged():
    nsgs = collect("any-any-rule.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.rule_name == "AllowAllInternet" for r in fails)


def test_any_any_missing_deny():
    nsgs = collect("any-any-rule.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "N/A" and "deny" in r.evidence.lower() for r in fails)


def test_any_any_empty_subnets():
    nsgs = collect("any-any-rule.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.11" for r in fails)


def test_empty_nsg_no_crashes():
    nsgs = collect("empty-nsg.json")
    results = run_engine(nsgs)
    assert isinstance(results, list)


def test_exposed_udp_flagged():
    nsgs = collect("exposed-udp.json")
    results = run_engine(nsgs)
    fails = [r for r in results if r.status == "fail"]
    assert any(r.control_id == "7.3" for r in fails)


def test_overly_broad_service_tags_fail():
    nsgs = collect("any-any-rule.json")
    fails = [r for r in check_overly_broad_service_tags(nsgs) if r.status == "fail"]
    assert len(fails) > 0
    assert any("all protocols" in r.evidence.lower() for r in fails)


def test_missing_asgs_fail():
    nsgs = collect("clean-nsg.json")
    fails = [r for r in check_missing_asgs(nsgs) if r.status == "fail"]
    assert len(fails) > 0
    assert any("10.0.0.0/8" in r.evidence for r in fails)


def test_missing_asgs_pass():
    nsgs = collect("empty-nsg.json")
    passes = [r for r in check_missing_asgs(nsgs) if r.status == "pass"]
    assert len(passes) > 0


def test_databricks_subnet_manual_when_none_found():
    nsgs = collect("empty-nsg.json")
    manuals = [r for r in check_databricks_subnet_nsg(nsgs) if r.status == "manual"]
    assert len(manuals) > 0


def test_stub_checks_return_manual():
    nsgs = collect("empty-nsg.json")
    stubs = [
        check_nsg_flow_logs_to_log_analytics,
        check_vnet_flow_logs_to_log_analytics,
        check_alert_create_update_nsg,
        check_alert_delete_nsg,
        check_network_watcher_enabled,
        check_network_security_perimeter,
        check_ddos_protection,
    ]
    for stub in stubs:
        results = stub(nsgs)
        assert all(r.status == "manual" for r in results), f"{stub.__name__} did not return manual"


def test_nsg_flow_log_retention_pass():
    nsgs = collect("clean-nsg.json")
    flow_logs = collect_flow_logs("flow-logs.json")
    results = check_nsg_flow_log_retention(nsgs, flow_logs)
    passes = [r for r in results if r.status == "pass"]
    assert any("clean-nsg" in r.nsg_name for r in passes)


def test_nsg_flow_log_retention_short_retention():
    nsgs = collect("violation-nsg.json")
    flow_logs = collect_flow_logs("flow-logs.json")
    results = check_nsg_flow_log_retention(nsgs, flow_logs)
    fails = [r for r in results if r.status == "fail"]
    assert any("30" in r.evidence for r in fails)


def test_nsg_flow_log_retention_disabled():
    nsgs = collect("any-any-rule.json")
    flow_logs = collect_flow_logs("flow-logs.json")
    results = check_nsg_flow_log_retention(nsgs, flow_logs)
    fails = [r for r in results if r.status == "fail"]
    assert any("not enabled" in r.evidence.lower() for r in fails)


def test_nsg_flow_log_retention_no_flow_log():
    nsgs = collect("empty-nsg.json")
    results = check_nsg_flow_log_retention(nsgs, [])
    fails = [r for r in results if r.status == "fail"]
    assert any("no flow log" in r.evidence.lower() for r in fails)


def test_vnet_flow_log_retention_returns_manual_when_no_vnet_logs():
    nsgs = collect("empty-nsg.json")
    flow_logs = collect_flow_logs("flow-logs.json")
    results = check_vnet_flow_log_retention(nsgs, flow_logs)
    assert all(r.status == "manual" for r in results)
