"""Tiny Elasticsearch/Kibana HTTP client using only the Python standard library."""

import json
import os
import urllib.error
import urllib.request

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")


def _request(url, method="GET", body=None, headers=None, ndjson=False):
    headers = dict(headers or {})
    data = None
    if body is not None:
        if ndjson:
            data = body.encode()
            headers["Content-Type"] = "application/x-ndjson"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {e.code}: {detail[:500]}") from None


def es(path, method="GET", body=None):
    return _request(f"{ES_URL}{path}", method, body)


def kibana(path, method="GET", body=None):
    return _request(f"{KIBANA_URL}{path}", method, body, headers={"kbn-xsrf": "true"})


def bulk_index(index, docs, id_fn=None):
    """Index a list of dicts. If id_fn is given, id_fn(doc) becomes the _id (makes re-indexing idempotent)."""
    if not docs:
        return 0
    lines = []
    for d in docs:
        meta = {"index": {"_index": index}}
        if id_fn:
            meta["index"]["_id"] = id_fn(d)
        lines.append(json.dumps(meta))
        lines.append(json.dumps(d))
    resp = _request(f"{ES_URL}/_bulk", "POST", "\n".join(lines) + "\n", ndjson=True)
    if resp.get("errors"):
        first = next(i for i in resp["items"] if i["index"].get("error"))
        raise RuntimeError(f"Bulk indexing error: {first['index']['error']}")
    return len(docs)


def search_window(index, start_iso, end_iso, size=10000):
    """Return all docs with @timestamp in [start, end)."""
    body = {
        "size": size,
        "sort": [{"@timestamp": "asc"}],
        "query": {"range": {"@timestamp": {"gte": start_iso, "lt": end_iso}}},
    }
    resp = es(f"/{index}/_search", "POST", body)
    return [h["_source"] for h in resp["hits"]["hits"]]
