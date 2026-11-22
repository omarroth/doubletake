"""Run the packaged sender and measure the local receiver's presentation."""
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import sys
import time

mode, sender, receiver, reports, work = sys.argv[1:]
reports = Path(reports)
receiver_log = reports / "receiver.log"
sender_log = reports / "sender.log"
sample_seconds = 8
fps = 24


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise


def cpu_seconds(pid):
    # comm is parenthesized and may contain spaces. utime/stime are fields 14/15.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def stats(line):
    return dict(re.findall(r"(\w+)=([^\s]+)", line))


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def latest_audio_samples():
    for line in reversed(receiver_log.read_text().splitlines()):
        if line.startswith("stats:"):
            return int(stats(line).get("audio_played", 0))
    return 0


with receiver_log.open("w") as output:
    sink = subprocess.Popen(
        [receiver, "-listen", "127.0.0.1:0", "-profile",
         "uxplay" if mode == "x11" else "lg", "-ntp", "-video-probe",
         "-stats-interval", "250ms"], stdout=output, stderr=subprocess.STDOUT,
    )
    source = None
    try:
        ready = time.monotonic() + 10
        while time.monotonic() < ready and sink.poll() is None:
            match = re.search(r"listening on 127\.0\.0\.1:(\d+)", receiver_log.read_text())
            if match:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("receiver failed to start")

        with sender_log.open("w") as log:
            started = time.monotonic()
            source = subprocess.Popen(
                [sender, "-target", "127.0.0.1", "-port", match[1],
                 "-creds", str(Path(work) / "credentials.json"),
                 "-audio-sink", "monitor", "-hwaccel", "none",
                 "-video-codec", "h264", "-resolution", "640x360",
                 "-fps", str(fps), "-bitrate", "1500", "-no-cursor",
                 "-target-latency-ms", "300"], stdout=log, stderr=subprocess.STDOUT,
            )
            first_marker = None
            while time.monotonic() - started < 25:
                if source.poll() is not None or sink.poll() is not None:
                    raise RuntimeError("sender or receiver stopped before playback started")
                if "video-probe:" in receiver_log.read_text():
                    first_marker = time.monotonic()
                    break
                time.sleep(0.1)
            if first_marker is None:
                raise RuntimeError("receiver never presented a timestamp from the desktop")

            # Let the decoder and audio pipeline warm up before measuring.
            time.sleep(1)
            begin_wall = time.time_ns() // 1_000_000
            begin = time.monotonic()
            begin_cpu = cpu_seconds(source.pid)
            begin_audio = latest_audio_samples()
            time.sleep(sample_seconds)
            elapsed = time.monotonic() - begin
            end_wall = time.time_ns() // 1_000_000
            cpu = cpu_seconds(source.pid) - begin_cpu
            audio_samples = latest_audio_samples() - begin_audio
    finally:
        try:
            sender_status = stop(source) if source else None
        finally:
            receiver_status = stop(sink)

lines = receiver_log.read_text().splitlines()
final = stats(next(line for line in reversed(lines) if line.startswith("final stats:")))
samples = []
seen = set()
for line in lines:
    if not line.startswith("video-probe:"):
        continue
    entry = stats(line)
    if begin_wall <= int(entry["presented_ms"]) < end_wall and entry["marker"] not in seen:
        seen.add(entry["marker"])
        samples.append(int(entry["latency_ms"]))

report = {
    "os": platform.freedesktop_os_release().get("PRETTY_NAME"),
    "kernel": platform.release(),
    "gstreamer": subprocess.check_output(["gst-launch-1.0", "--version"], text=True).splitlines()[1],
    "doubletake": subprocess.check_output([sender, "-version"], text=True).strip(),
    "session": mode,
    "requested_fps": fps,
    "seconds": round(elapsed, 2),
    "startup_seconds": round(first_marker - started, 2),
    "unique_presented_fps": round(len(samples) / elapsed, 2),
    "presented_markers": len(samples),
    "video_latency_ms": {
        "p50": statistics.median(samples) if samples else None,
        "p95": percentile(samples, 0.95) if samples else None,
        "max": max(samples) if samples else None,
    },
    "sender_cpu_percent_of_one_core": round(100 * cpu / elapsed, 2),
    "audio_samples_per_second": round(audio_samples / elapsed),
    "receiver": final,
}
(report_path := reports / "playback.json").write_text(json.dumps(report, indent=2) + "\n")
print(report_path.read_text(), end="")
if sender_status or receiver_status:
    raise SystemExit(f"Nonzero shutdown status: sender={sender_status}, receiver={receiver_status}")
# Wide regression limits accommodate shared VM scheduling. Keep exact results
# in the report to compare runs without treating them as hardware benchmarks.
if len(samples) / elapsed < 16 or percentile(samples, .95) > 600 or max(samples) > 1200:
    raise SystemExit("Desktop video throughput or presentation latency missed the CI budget")
if audio_samples / elapsed < 44100 * 0.85:
    raise SystemExit("Receiver played too few audio samples")
if not 100 <= int(final.get("audio_peak", 0)) <= 2000:
    raise SystemExit("Receiver did not decode the expected test tone level")
