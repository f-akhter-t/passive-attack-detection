# Live Demonstration Guide

## Purpose

This demonstration showcases the passive attack detection pipeline operating on live network traffic.

A short packet capture is collected from the attacker VM, converted into behavioral features, and evaluated using the pre-trained Isolation Forest model. Detection results are displayed immediately after the capture.

---

## Requirements

Start the following virtual machines before running the demo:

- Attacker-Kali
- Client-1
- Client-2
- Client-3
- Server

Ensure that the normal traffic generation scripts are already running on the client and server virtual machines.

---

## Running the Demonstration

From the project root:

```bash
sudo bash demo/demo_capture_and_analyze.sh
```

Optional parameters:

```bash
sudo bash demo/demo_capture_and_analyze.sh <duration_seconds> <interface>
```

Example:

```bash
sudo bash demo/demo_capture_and_analyze.sh 90 eth0
```

---

## Demonstration Workflow

The script performs the following steps:

1. Verifies connectivity to all client and server virtual machines.
2. Captures live network traffic using `tcpdump`.
3. Extracts behavioral features from the packet capture.
4. Loads the trained Isolation Forest model.
5. Scores every device window.
6. Displays detected anomalies.

No retraining is performed during the demonstration.

---

## Generated Files

Temporary demonstration files are written to:

```
demo/captures/
demo/results/
```

These directories are excluded from version control through `.gitignore`.

---

## Notes

The demonstration uses the trained baseline model contained in:

```
models/c08_fixed/
```

The live capture is evaluated only against this existing model. The baseline is not modified during the demonstration.
