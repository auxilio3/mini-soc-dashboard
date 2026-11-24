# Building the SOC dashboard in Kibana

You build the dashboard yourself in Kibana. It takes about 30-45 minutes, and you'll be able to explain every panel in an interview. When you're done, you export it to `dashboards/mini-soc-dashboard.ndjson` so anyone can import it with one click.

**Before you start**, load some data so the panels have something to show:

```bash
python3 -m soc.generate --backfill-hours 6
python3 -m soc.detect --backfill-hours 6
```

## Severity colors (from the capstone design)

| Severity | Color | Hex |
|---|---|---|
| Critical | Red | `#D7263D` |
| High | Orange | `#F46036` |
| Medium | Yellow | `#F2C14E` |
| Low | Blue | `#2E86AB` |

In Lens, open the color settings of any chart broken down by `alert.severity`, switch to **Color mapping**, and assign each value its color by hand. Use the same colors in every panel.

## Panels

Go to **Analytics → Dashboards → Create dashboard → Create visualization**. Each panel is a Lens visualization on the **soc-alerts** data view unless noted.

| # | Panel | Lens type | Setup |
|---|---|---|---|
| 1 | **Open alerts** | Metric | Count of records |
| 2 | **Critical alerts** | Metric | Count, with filter `alert.severity : "Critical"`, color red |
| 3 | **Alerts by severity** | Donut | Slice by `alert.severity`, severity colors |
| 4 | **Alerts over time** | Bar vertical stacked | X: `@timestamp`, Y: count, Breakdown: `alert.severity`, severity colors |
| 5 | **Alerts by detection rule** | Bar horizontal | Rows: `rule.name` (top 8), Y: count |
| 6 | **Top source IPs** | Table | Rows: `source.ip` (top 10), Metric: count, plus a column for top `rule.name` |
| 7 | **MITRE ATT&CK techniques** | Treemap | Group by `threat.technique.id` |
| 8 | **Telemetry volume** *(soc-events data view)* | Line | X: `@timestamp`, Y: count, Breakdown: `event.category` |
| 9 | **Detection quality (lab only)** | Bar horizontal | Rows: `rule.name`, Breakdown: `labels.ground_truth`. Look-alikes or benign showing up here = false positives |

**Alert feed:** in **Discover**, choose the soc-alerts data view and add the columns `alert.severity`, `rule.name`, `message`, `host.name`, `source.ip`. Sort by `@timestamp` descending, save it as "Alert feed", then add it to the dashboard with **Add from library**.

**Layout tip:** put the metric tiles across the top, then the donut and the stacked bar, then the rule/IP/MITRE panels, and the alert feed full-width at the bottom.

## Auto-refresh every 30 seconds

In the time picker: **Last 24 hours**, then click the calendar icon and under **Refresh every** enter **30 seconds** and click Start. When you save the dashboard, check **Store time with dashboard** so the refresh setting is kept.

## Try it live

In two SSH windows:

```bash
python3 -m soc.generate          # window 1: live telemetry
python3 -m soc.detect            # window 2: detection engine
```

Then fire an attack on demand and watch it show up on the dashboard within 30 seconds:

```bash
python3 -m soc.generate --attack data_exfiltration
```

## Export it into the repo

**Stack Management → Saved Objects**, check the dashboard, then **Export** with "Include related objects" on. Save the file as `dashboards/mini-soc-dashboard.ndjson`, take a screenshot as `docs/screenshots/dashboard.png`, and commit both.

To import it on a fresh stack, go to **Saved Objects → Import** and choose the `.ndjson` file.
