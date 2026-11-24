"""Offline detection-accuracy test: no Elasticsearch needed.

Simulates N hours of traffic with attacks injected, replays it through the
detection engine the way live mode does (5-minute window every 30 seconds),
then compares the alerts against ground truth.

    python3 -m soc.evaluate --hours 24 --seed 7
"""

import argparse
import bisect
import random
from collections import Counter
from datetime import timedelta

from .detect import WINDOW, detect_window
from .events import iso, now, simulate
from .rules import RULES

RULE_ID_TO_SCENARIO = {f"UC{i}": name for i, name in enumerate(RULES, start=1)}


def evaluate(hours, seed, attacks_per_hour=6.0, step_seconds=30):
    random.seed(seed)
    start = now() - timedelta(hours=hours)
    events, injected = simulate(start, int(hours * 60), attacks_per_hour)
    stamps = [e["@timestamp"] for e in events]

    alerts = {}
    t = start + WINDOW
    end = start + timedelta(hours=hours)
    while t <= end:
        lo = bisect.bisect_left(stamps, iso(t - WINDOW))
        hi = bisect.bisect_left(stamps, iso(t))
        for a in detect_window(t, events[lo:hi]):
            alerts[a["alert"]["id"]] = a  # later runs update the same alert
        t += timedelta(seconds=step_seconds)

    # True positive: the alert's events came from the scenario its rule is meant to catch.
    tp = Counter()
    fp = []
    for a in alerts.values():
        expected = RULE_ID_TO_SCENARIO[a["rule"]["id"]]
        if expected in a["labels"]["ground_truth"]:
            tp[expected] += 1
        else:
            fp.append(a)

    detected = Counter()
    for name, t0 in injected:
        lo, hi = iso(t0 - timedelta(seconds=1)), iso(t0 + timedelta(minutes=6))
        if any(RULE_ID_TO_SCENARIO[a["rule"]["id"]] == name and lo <= a["alert"]["first_seen"] <= hi
               for a in alerts.values()):
            detected[name] += 1
    return len(events), injected, detected, tp, fp


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-tuning", action="store_true", help="disable allowlists/tuned thresholds")
    args = ap.parse_args()
    from . import rules
    rules.TUNING = not args.no_tuning

    n_events, injected, detected, tp, fp = evaluate(args.hours, args.seed)
    by_type = Counter(name for name, _ in injected)
    print(f"Tuning: {'ON' if not args.no_tuning else 'OFF'}")
    print(f"Simulated {args.hours:g}h: {n_events:,} events, {len(injected)} attacks injected (seed {args.seed})\n")
    print(f"{'Use case':<24}{'Injected':>9}{'Detected':>10}{'Rate':>8}")
    for name in RULES:
        inj, det = by_type[name], detected[name]
        rate = f"{det / inj:.0%}" if inj else "-"
        print(f"{name:<24}{inj:>9}{det:>10}{rate:>8}")
    total_det = sum(detected.values())
    print(f"\nOverall detection rate: {total_det}/{len(injected)} "
          f"({total_det / max(1, len(injected)):.0%})")
    print(f"False positives: {len(fp)}")
    for a in fp[:10]:
        print(f"  FP {a['rule']['id']} {a['message']}  (ground truth: {a['labels']['ground_truth']})")


if __name__ == "__main__":
    main()
