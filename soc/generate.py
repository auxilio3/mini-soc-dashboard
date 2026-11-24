"""Send simulated security telemetry to Elasticsearch.

    python3 -m soc.generate --backfill-hours 6   # write 6 hours of history, then exit
    python3 -m soc.generate                      # stream live events (Ctrl+C to stop)
    python3 -m soc.generate --attack brute_force # fire one attack scenario right now
"""

import argparse
import random
import time
from datetime import timedelta

from . import EVENTS_INDEX, es
from .events import ATTACKS, benign_events, now, simulate

# Attack scenarios spread their events over up to ~4 minutes after their start time.
# Starting them 4 minutes ago keeps every event in the past, so the detector sees it right away.
ATTACK_LEAD = timedelta(minutes=4)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backfill-hours", type=float, default=0)
    ap.add_argument("--attacks-per-hour", type=float, default=6.0)
    ap.add_argument("--attack", choices=sorted(ATTACKS), help="inject one attack scenario now and exit")
    ap.add_argument("--seed", type=int, help="random seed for repeatable runs")
    args = ap.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    if args.attack:
        n = es.bulk_index(EVENTS_INDEX, ATTACKS[args.attack](now() - ATTACK_LEAD))
        print(f"Injected '{args.attack}' ({n} events).")
        return

    if args.backfill_hours:
        start = now() - timedelta(hours=args.backfill_hours) - ATTACK_LEAD
        events, injected = simulate(start, int(args.backfill_hours * 60), args.attacks_per_hour)
        for i in range(0, len(events), 5000):
            es.bulk_index(EVENTS_INDEX, events[i:i + 5000])
        print(f"Wrote {len(events):,} events with {len(injected)} attacks over {args.backfill_hours}h.")
        return

    print("Streaming live events. Ctrl+C to stop.")
    step = 5
    p_attack = args.attacks_per_hour * step / 3600
    while True:
        t = now()
        batch = benign_events(t - timedelta(seconds=step), step)
        if random.random() < p_attack:
            name = random.choice(list(ATTACKS))
            batch += ATTACKS[name](t - ATTACK_LEAD)
            print(f"  -> attack injected: {name}")
        es.bulk_index(EVENTS_INDEX, batch)
        time.sleep(step)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
