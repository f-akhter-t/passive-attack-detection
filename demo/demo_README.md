# Live Demo Tooling

Scripts used to run a live, in-front-of-the-professor demonstration. These
are separate from the evaluated pipeline in the project root — nothing here
writes into `data/`, `models/`, or `results/`, so rehearsing the demo never
changes the reported numbers.

| Script | Where it runs | Purpose |
|---|---|---|
| `demo_banner.sh` | Attacker-Kali (called automatically by `run_full_pipeline.sh`) | Cosmetic title banner, team names/IDs |
| `demo_client_ping.sh <peer_ip>` | Client-1 and Client-2 | Visible ping traffic during the live capture window |
| `demo_capture_and_analyze.sh [duration] [interface]` | Attacker-Kali (project root) | Captures live traffic, extracts features, and scores it against the already-trained `models/c08_fixed/` model, printing a live anomaly table |

## Output locations

`demo_capture_and_analyze.sh` writes everything it produces into:
- `demo/captures/` — raw pcap + extracted features from the live run
- `demo/results/` — detection CSV from the live run

Both are gitignored; they're rehearsal artifacts, not reported results.

## Running the demo

From the project root, on Attacker-Kali:
```
sudo bash demo/demo_capture_and_analyze.sh 90 eth0
```
On Client-1 and Client-2, in parallel:
```
bash demo/demo_client_ping.sh <peer_ip>
```

Full timed run sheet with narration cues is kept separately (not committed
to this repo) as a printed cheat sheet for the presenter.
