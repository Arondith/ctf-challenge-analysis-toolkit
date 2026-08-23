from __future__ import annotations

import asyncio
import math
import wave
from collections import Counter
from pathlib import Path

import numpy as np
from fastapi import HTTPException

from backend import main as core
from backend import workbench as wb


BASE_CATALOG = wb.analysis_catalog
BASE_EXECUTE = wb.execute_analysis
MAX_AUDIO_SECONDS = 180.0
MAX_SEGMENTS = 400
FFT_SAMPLES = 8192


def _read_pcm(path: Path) -> tuple[int, np.ndarray]:
    with wave.open(str(path), "rb") as handle:
        channels = handle.getnchannels()
        width = handle.getsampwidth()
        rate = handle.getframerate()
        frames = handle.getnframes()
        if rate <= 0 or frames <= 0:
            raise ValueError("Invalid WAV sample rate/frame count.")
        if frames / rate > MAX_AUDIO_SECONDS:
            raise ValueError(f"WAV is longer than the {MAX_AUDIO_SECONDS:.0f}s automatic tone-analysis limit.")
        raw = handle.readframes(frames)

    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}.get(width)
    if dtype is None:
        raise ValueError(f"Unsupported PCM sample width: {width} bytes.")
    samples = np.frombuffer(raw, dtype=dtype)
    if width == 1:
        samples = samples.astype(np.float32) - 128.0
    else:
        samples = samples.astype(np.float32)
    if channels > 1:
        usable = (len(samples) // channels) * channels
        samples = samples[:usable].reshape(-1, channels).mean(axis=1)
    return rate, samples


def _dominant_frequency(samples: np.ndarray, rate: int) -> float:
    if len(samples) < 64:
        return 0.0
    size = min(len(samples), FFT_SAMPLES)
    start = max(0, (len(samples) - size) // 2)
    x = samples[start:start + size].astype(np.float64, copy=False)
    x = x - float(np.mean(x))
    if not np.any(x):
        return 0.0
    x = x * np.hanning(len(x))
    spectrum = np.abs(np.fft.rfft(x))
    freqs = np.fft.rfftfreq(len(x), 1.0 / rate)
    spectrum[freqs < 20.0] = 0.0
    index = int(np.argmax(spectrum))
    return float(freqs[index])


def _probe(samples: np.ndarray, rate: int, count: int) -> list[int]:
    result: list[int] = []
    total = len(samples)
    for index in range(count):
        start = index * total // count
        end = (index + 1) * total // count
        freq = _dominant_frequency(samples[start:end], rate)
        # 25-Hz quantization is tight enough to separate common CTF tones while
        # suppressing small FFT-bin drift.
        result.append(int(round(freq / 25.0) * 25))
    return result


def _grid_coordinates(values: list[int], side: int, target: int) -> list[str]:
    coords: list[str] = []
    for index, value in enumerate(values):
        if value != target:
            continue
        row = index // side + 1
        col_index = index % side
        if side <= 26:
            column = chr(ord("A") + col_index)
        else:
            column = str(col_index + 1)
        coords.append(f"{column}{row}")
    return coords


def tone_report(row) -> str:
    path = Path(row["path"])
    rate, samples = _read_pcm(path)
    duration = len(samples) / rate

    counts: set[int] = {64, 81, 100, 121, 144}
    for step in (0.1, 0.2, 0.25, 0.5, 1.0):
        count = int(round(duration / step))
        if 4 <= count <= MAX_SEGMENTS:
            counts.add(count)

    probes: list[tuple[tuple[int, int, int], int, list[int], Counter]] = []
    for count in sorted(counts):
        if count > MAX_SEGMENTS or len(samples) // count < 128:
            continue
        values = _probe(samples, rate, count)
        clusters = Counter(values)
        nonzero = {freq: hits for freq, hits in clusters.items() if freq > 0}
        if not nonzero:
            continue
        side = math.isqrt(count)
        square_penalty = 0 if side * side == count else 1
        # Prefer clean low-cardinality tone alphabets and square layouts, which
        # are common for audio-encoded grid CTFs.
        score = (len(nonzero), square_penalty, count)
        probes.append((score, count, values, Counter(nonzero)))

    if not probes:
        return f"WAV duration: {duration:.6f}s\nSample rate: {rate} Hz\nNo stable tone probe could be produced."

    probes.sort(key=lambda item: item[0])
    selected = probes[:6]
    out = [
        f"WAV duration: {duration:.6f}s",
        f"Sample rate: {rate} Hz",
        f"Samples: {len(samples)}",
        "Repeated-tone equal-segment probes:",
    ]

    # Always include a 100-cell probe when available because a 10x10 grid is a
    # common challenge representation; also include the best-scoring probes.
    by_count = {item[1]: item for item in probes}
    ordered = []
    if 100 in by_count:
        ordered.append(by_count[100])
    for item in selected:
        if item not in ordered:
            ordered.append(item)

    for _, count, values, clusters in ordered[:7]:
        segment_seconds = duration / count
        cluster_text = ", ".join(f"{freq} Hz x{hits}" for freq, hits in clusters.most_common())
        out.append(f"\nN={count} · segment={segment_seconds:.6f}s · clusters: {cluster_text}")

        side = math.isqrt(count)
        if side * side == count and side <= 26 and len(clusters) <= 8:
            out.append(f"{side}x{side} frequency grid (row-major, columns A-{chr(ord('A') + side - 1)}):")
            for row_index in range(side):
                row_values = values[row_index * side:(row_index + 1) * side]
                out.append(" ".join(f"{value:4d}" for value in row_values))

            if len(clusters) >= 2:
                minority_freq, minority_hits = min(clusters.items(), key=lambda item: item[1])
                majority_freq, majority_hits = max(clusters.items(), key=lambda item: item[1])
                minority_coords = _grid_coordinates(values, side, minority_freq)
                out.append(
                    f"Minority cluster: {minority_freq} Hz x{minority_hits}; "
                    f"majority cluster: {majority_freq} Hz x{majority_hits}"
                )
                out.append("Minority cluster coordinates: " + ", ".join(minority_coords))

    return "\n".join(out)


async def tone_analysis(conn, row, analysis_id: str, label: str):
    try:
        output = await asyncio.to_thread(tone_report, row)
        status, rc = "complete", 0
    except Exception as exc:
        output = f"{type(exc).__name__}: {exc}"
        status, rc = "error", 1
    output = wb.trim_output(output)
    found = wb.insert_flags_from_text(conn, row, output, label)
    run_id = wb.record_run(conn, row["id"], analysis_id, label, ["python", "<tone-sequence>"], output, rc, status)
    return {
        "id": run_id,
        "analysis_id": analysis_id,
        "label": label,
        "status": status,
        "returncode": rc,
        "output": output,
        "flags": found,
    }


def audio_signal_catalog(row):
    catalog = BASE_CATALOG(row)
    suffix = Path(row["filename"]).suffix.lower()
    if row["kind"] == "wav" or suffix == ".wav":
        catalog["audio.tone-sequence"] = {
            "label": "Repeated tone / grid sequence decoder",
            "tool": "python",
            "argv": ["python"],
            "auto": True,
            "special": "audio-tone-sequence",
        }
    return catalog


async def audio_signal_execute(conn, row, analysis_id: str):
    catalog = audio_signal_catalog(row)
    spec = catalog.get(analysis_id)
    if not spec:
        raise HTTPException(400, "Analysis is not available for this artifact type.")
    if spec.get("special") == "audio-tone-sequence":
        return await tone_analysis(conn, row, analysis_id, spec["label"])
    return await BASE_EXECUTE(conn, row, analysis_id)


wb.analysis_catalog = audio_signal_catalog
wb.execute_analysis = audio_signal_execute
