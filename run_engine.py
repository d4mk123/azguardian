from pathlib import Path

from azguardian.collector import collect_from_file
from azguardian.rule_engine import run_engine

FIXTURES_DIR = Path("test-data")

fixtures = sorted(FIXTURES_DIR.glob("*.json"))
for fixture_path in fixtures:

    print(f"{'='*60}")
    print(f"Fixtures: {fixture_path.name}")
    print(f"{'='*60}")
    try:
        nsgs = collect_from_file(fixture_path)
    except Exception as e:
        print(f"  Error loading fixture: {e}")
        print()
        continue
    results = run_engine(nsgs)
    passes = [r for r in results if r.status == "pass"]
    fails = [r for r in results if r.status == "fail"]
    manuels = [r for r in results if r.status == "manual"]
    print(f"  Pass: {len(passes)}  Fail: {len(fails)}  Manual: {len(manuels)}")
    for r in results:
        status_icon = "PASS" if r.status == "pass" else "FAIL" if r.status == "fail" else "MANU"
        print(f"  [{status_icon}] {r.control_id:7} | {r.severity:8} | {r.evidence[:70]}")
    print()
