"""One-time setup: index templates in Elasticsearch and data views in Kibana.

    python3 -m soc.setup_stack
"""

import time

from . import ALERTS_INDEX, EVENTS_INDEX, es

KW = {"type": "keyword"}
IP = {"type": "ip"}

EVENT_MAPPINGS = {
    "properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"category": KW, "action": KW, "outcome": KW, "reason": KW}},
        "labels": {"properties": {"scenario": KW}},
        "user": {"properties": {"name": KW, "target": {"properties": {"name": KW}}}},
        "host": {"properties": {"name": KW}},
        "source": {"properties": {"ip": IP}},
        "destination": {"properties": {"ip": IP, "port": {"type": "integer"}}},
        "network": {"properties": {"bytes": {"type": "long"}}},
        "process": {"properties": {"name": KW, "command_line": {"type": "text", "fields": {"keyword": KW}}}},
        "file": {"properties": {"hash": {"properties": {"sha256": KW}}}},
        "group": {"properties": {"name": KW}},
    }
}

ALERT_MAPPINGS = {
    "properties": {
        **EVENT_MAPPINGS["properties"],
        "rule": {"properties": {"id": KW, "name": KW}},
        "alert": {"properties": {
            "id": KW, "severity": KW, "severity_score": {"type": "integer"}, "key": KW,
            "event_count": {"type": "integer"}, "status": KW,
            "first_seen": {"type": "date"}, "last_seen": {"type": "date"}, "detected_at": {"type": "date"},
        }},
        "threat": {"properties": {"technique": {"properties": {"id": KW}}}},
        "message": {"type": "text"},
        "labels": {"properties": {"ground_truth": KW}},
    }
}


def wait_for(fn, what, tries=60):
    for _ in range(tries):
        try:
            return fn()
        except Exception:
            print(f"Waiting for {what}...")
            time.sleep(5)
    raise SystemExit(f"{what} did not come up. Is the stack running? Try: docker compose ps")


def main():
    wait_for(lambda: es.es("/_cluster/health"), "Elasticsearch")
    for name, index, mappings in [("soc-events", EVENTS_INDEX, EVENT_MAPPINGS),
                                  ("soc-alerts", ALERTS_INDEX, ALERT_MAPPINGS)]:
        es.es(f"/_index_template/{name}", "PUT", {
            "index_patterns": [f"{index}*"],
            "template": {"settings": {"number_of_replicas": 0}, "mappings": mappings},
        })
        print(f"Index template '{name}' ready.")

    wait_for(lambda: es.kibana("/api/status"), "Kibana")
    for view_id, index in [("soc-events", EVENTS_INDEX), ("soc-alerts", ALERTS_INDEX)]:
        try:
            es.kibana("/api/data_views/data_view", "POST", {
                "data_view": {"id": view_id, "title": f"{index}*", "name": index, "timeFieldName": "@timestamp"},
                "override": True,
            })
            print(f"Kibana data view '{index}' ready.")
        except RuntimeError as e:
            print(f"Could not create data view '{index}': {e}")
    print("\nSetup done. Next: python3 -m soc.generate --backfill-hours 6")


if __name__ == "__main__":
    main()
