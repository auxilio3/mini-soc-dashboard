"""Detection engine: every 30 seconds, run the 8 rules over the last 5 minutes of events.

    python3 -m soc.detect                     # live mode (Ctrl+C to stop)
    python3 -m soc.detect --backfill-hours 6  # scan history once, then exit
"""

import argparse
import hashlib
import time
from datetime import datetime, timedelta, timezone

from . import ALERTS_INDEX, EVENTS_INDEX, es
from .events import iso, now
from .rules import run_all

WINDOW = timedelta(minutes=5)
DEDUP_BUCKET_MINUTES = 10


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def finalize(alert, detected_at):
    """Add @timestamp and a stable ID so re-detecting the same activity updates one alert."""
    first = _parse(alert["alert"]["first_seen"])
    bucket = first.replace(minute=first.minute - first.minute % DEDUP_BUCKET_MINUTES, second=0, microsecond=0)
    raw = f"{alert['rule']['id']}|{alert['alert']['key']}|{bucket.isoformat()}"
    alert["alert"]["id"] = hashlib.sha1(raw.encode()).hexdigest()[:20]
    alert["@timestamp"] = alert["alert"]["last_seen"]
    alert["alert"]["detected_at"] = iso(detected_at)
    return alert


def detect_window(end, events=None):
    start = end - WINDOW
    if events is None:
        events = es.search_window(EVENTS_INDEX, iso(start), iso(end))
    return [finalize(a, end) for a in run_all(events)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=int, default=30, help="seconds between runs (default 30)")
    ap.add_argument("--backfill-hours", type=float, default=0, help="scan this much history once and exit")
    args = ap.parse_args()

    if args.backfill_hours:
        t = now() - timedelta(hours=args.backfill_hours) + WINDOW
        total = 0
        while t <= now():
            alerts = detect_window(t)
            total += _index(alerts)
            t += timedelta(seconds=args.interval)
        print(f"Backfill complete: wrote {total} alert updates.")
        return

    print(f"Detection engine running every {args.interval}s over a {WINDOW} window. Ctrl+C to stop.")
    while True:
        alerts = detect_window(now())
        _index(alerts)
        if alerts:
            for a in alerts:
                print(f"[{a['alert']['severity']:>8}] {a['rule']['name']}: {a['message']}")
        time.sleep(args.interval)


def _index(alerts):
    return es.bulk_index(ALERTS_INDEX, alerts, id_fn=lambda a: a["alert"]["id"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
