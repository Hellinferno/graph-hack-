"""AegisGraph — Automated Hackathon Demo Video Generator.

Generates synchronized AI voiceover narration using Windows SpeechSynthesizer,
records the full 1080p interactive walkthrough via Playwright, and muxes them
into a high-definition MP4 video (`aegisgraph_demo.mp4`) using FFmpeg.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import wave
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
TEMP_DIR = ROOT / "scripts" / "video_temp"
OUTPUT_VIDEO = ROOT / "aegisgraph_demo.mp4"
TTS_SCRIPT = ROOT / "scripts" / "generate_tts.ps1"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

SCENES = [
    {
        "id": "scene_1_intro",
        "title": "Introduction & Topology Overview",
        "narration": (
            "Welcome to AegisGraph — an MCP-native incident remediation agent powered by FalkorDB "
            "for the WeMakeDevs Graph Hacks hackathon. When a vulnerability alert strikes a production cluster, "
            "security engineers face a critical dilemma: what customer data is truly exposed, and what can we cut "
            "without taking critical services offline? Traditional vector databases only match keywords, and relational "
            "databases require complex recursive joins. AegisGraph grounds every decision in a unified FalkorDB knowledge graph."
        ),
    },
    {
        "id": "scene_2_incident",
        "title": "Incident Selection & Hybrid Vector Anchoring",
        "narration": (
            "In the control console, a live security incident arrives: WAF observed 1,240 forged bearer tokens "
            "accepted by auth-token-service, with signature bypass suspected in the jwt-crypto-core library. "
            "AegisGraph checks its episodic memory graph for past playbooks, then anchors the raw alert using FalkorDB's "
            "hybrid vector and full-text indexes. It pinpoints CVE-2026-8841 in package jwt-crypto-core."
        ),
    },
    {
        "id": "scene_3_blast_radius",
        "title": "Deep Blast Radius Traversal",
        "narration": (
            "With the entry point anchored, AegisGraph executes a multi-hop Cypher traversal spanning code dependencies, "
            "service routes, IAM roles, and databases. It uncovers 6 active attack paths into 3 production databases containing "
            "sensitive customer PII: the customer KYC vault, the global settlement ledger, and the reporting warehouse. "
            "Notice how all six attack paths funnel through one specific service: legacy-billing-bridge."
        ),
    },
    {
        "id": "scene_4_chokepoint",
        "title": "Chokepoint Identification with Native Graph Algorithms",
        "narration": (
            "Which entity should the agent isolate? Rather than guessing, AegisGraph calls FalkorDB's native graph algorithms "
            "directly through MCP tools. Betweenness centrality reveals that legacy-billing-bridge has the highest betweenness "
            "score of 6.0 across all services. The runner-up, payment-orchestrator, is critical-tier handling 3,100 requests per "
            "second. AegisGraph protects critical infrastructure and selects the bridge as the optimal chokepoint."
        ),
    },
    {
        "id": "scene_5_sandbox",
        "title": "Counterfactual Sandbox Simulation",
        "narration": (
            "Before modifying production, AegisGraph clones the entire environment into an isolated sandbox graph using FalkorDB's "
            "GRAPH.COPY procedure. In the sandbox, it severs the bridge and tests the fix: exposure drops from 6 to 0, all 4 critical "
            "customer transaction flows remain intact, and weakly connected components confirm the cluster is undamaged. The simulation "
            "mathematically proves the fix is safe."
        ),
    },
    {
        "id": "scene_6_remediation",
        "title": "Surgical Remediation & Autonomous PR Routing",
        "narration": (
            "Having proven safety in the sandbox, AegisGraph executes the remediation on the production graph. It isolates the bridge "
            "and quarantines its IAM role using reversible status flags. Through the graph's maintainer relationships, it identifies "
            "the on-call engineer, Aarav, and drafts a pull request bumping jwt-crypto-core to version 2.4.2. A live re-trace confirms "
            "exposure has reached zero."
        ),
    },
    {
        "id": "scene_7_audit",
        "title": "Decision Proof, Cypher Audit & Conclusion",
        "narration": (
            "Every single decision is fully auditable. The agent records an ActionAudit node in the graph, linked to the incident "
            "with the exact Cypher statements and centrality scores. If necessary, a single rollback call reverts all mutations cleanly. "
            "Without FalkorDB, none of this would be possible. AegisGraph demonstrates the power of agents acting on connected data. "
            "Thank you!"
        ),
    },
]


def get_wav_duration(path: Path) -> float:
    with wave.open(str(path), "rb") as w:
        frames = w.getnframes()
        rate = w.getframerate()
        return frames / float(rate)


def generate_audio_tracks() -> list[tuple[dict, Path, float]]:
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    print("\n--- Step 1: Generating Scene Voiceovers ---")
    for scene in SCENES:
        wav_file = TEMP_DIR / f"{scene['id']}.wav"
        print(f"Generating audio for {scene['title']}...")
        cmd = [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(TTS_SCRIPT),
            "-Text",
            scene["narration"],
            "-OutputFile",
            str(wav_file),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        duration = get_wav_duration(wav_file)
        print(f"  -> Duration: {duration:.1f}s")
        results.append((scene, wav_file, duration))
    return results


def concatenate_audio(tracks: list[tuple[dict, Path, float]]) -> Path:
    print("\n--- Step 2: Merging Complete Narration Soundtrack ---")
    concat_list = TEMP_DIR / "concat_list.txt"
    with open(concat_list, "w", encoding="utf-8") as f:
        for _, wav_path, _ in tracks:
            # Escape path for ffmpeg concat
            normalized = str(wav_path.resolve()).replace("\\", "/")
            f.write(f"file '{normalized}'\n")

    full_audio = TEMP_DIR / "full_narration.wav"
    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(concat_list),
        "-c:a",
        "pcm_s16le",
        str(full_audio),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    total_duration = get_wav_duration(full_audio)
    print(f"Complete soundtrack generated: {total_duration:.1f}s total ({int(total_duration // 60)}m {int(total_duration % 60)}s)")
    return full_audio


def record_browser_session(tracks: list[tuple[dict, Path, float]]) -> Path:
    print("\n--- Step 3: Reseeding Demo Graph State ---")
    py = ROOT / ".venv" / "Scripts" / "python.exe"
    subprocess.run([str(py), "-m", "aegis", "seed", "--reset-memory"], cwd=ROOT / "backend", check=True, stdout=subprocess.DEVNULL)

    video_record_dir = TEMP_DIR / "raw_video"
    if video_record_dir.exists():
        shutil.rmtree(video_record_dir)
    video_record_dir.mkdir(parents=True, exist_ok=True)

    print("\n--- Step 4: Recording Browser Walkthrough via Playwright ---")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=CHROME_PATH,
            headless=True,
            args=["--start-maximized", "--no-sandbox", "--disable-gpu"],
        )
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(video_record_dir),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = context.new_page()

        print("Navigating to http://localhost:5173...")
        page.goto("http://localhost:5173", wait_until="networkidle")
        page.wait_for_selector(".graph canvas", timeout=15000)
        time.sleep(1)

        for scene, _, duration in tracks:
            scene_id = scene["id"]
            print(f"Recording: {scene['title']} (target duration {duration:.1f}s)...")
            start_t = time.time()

            if scene_id == "scene_1_intro":
                # Overview of idle topology
                page.mouse.move(960, 540)
                time.sleep(2)
                # Hover brand and counts
                page.hover(".brand")
                time.sleep(2)
                page.hover(".counts")
                time.sleep(2)
                page.mouse.move(750, 480)

            elif scene_id == "scene_2_incident":
                # Select INC-2026-091
                incidents = page.locator(".incident")
                if incidents.count() > 0:
                    incidents.first.click()
                time.sleep(1.5)
                # Select Auto or Deterministic mode
                mode_btn = page.locator(".segmented__item:has-text('Deterministic')")
                if mode_btn.is_visible():
                    mode_btn.click()
                time.sleep(1)
                # Click Investigate & remediate
                page.locator("button:has-text('Investigate & remediate')").click()

            elif scene_id == "scene_3_blast_radius":
                # Wait for attack paths
                try:
                    page.wait_for_selector(".paths__row", timeout=12000)
                except Exception:
                    pass
                time.sleep(1.5)
                # Hover over the canvas and attack paths
                page.hover(".paths")
                time.sleep(2)
                page.mouse.move(900, 500)

            elif scene_id == "scene_4_chokepoint":
                # Scroll right panel to candidate chokepoints and centrality table
                page.evaluate('document.querySelector(".panel--right")?.scrollBy({top: 320, behavior: "smooth"})')
                time.sleep(2)
                page.hover("tr.is-bridge")
                time.sleep(2)

            elif scene_id == "scene_5_sandbox":
                # Click View sandbox graph if available
                sandbox_btn = page.locator("button:has-text('View sandbox graph')")
                if sandbox_btn.is_visible():
                    sandbox_btn.click()
                    time.sleep(3.5)
                    back_btn = page.locator("button:has-text('Back to production graph')")
                    if back_btn.is_visible():
                        back_btn.click()
                time.sleep(1.5)

            elif scene_id == "scene_6_remediation":
                # Scroll to Action Taken and PR draft
                page.evaluate('document.querySelector(".panel--right")?.scrollBy({top: 380, behavior: "smooth"})')
                time.sleep(2)
                pr_summary = page.locator(".pr details summary")
                if pr_summary.is_visible():
                    pr_summary.click()
                time.sleep(2)

            elif scene_id == "scene_7_audit":
                # Scroll right panel back to top
                page.evaluate('document.querySelector(".panel--right")?.scrollTo({top: 0, behavior: "smooth"})')
                time.sleep(1.5)
                # Expand a tool trace in left panel
                trace_head = page.locator(".trace__head")
                if trace_head.count() > 0:
                    trace_head.first.click()
                time.sleep(2)

            # Pad remaining time for this scene to match audio duration precisely
            elapsed = time.time() - start_t
            remaining = duration - elapsed
            if remaining > 0:
                time.sleep(remaining)

        # Extra 2s outro buffer
        time.sleep(2)
        print("Closing browser and flushing video...")
        page.close()
        context.close()
        browser.close()

    # Find the recorded webm file
    webm_files = list(video_record_dir.glob("*.webm"))
    if not webm_files:
        raise RuntimeError("No recorded video found in Playwright video dir!")
    print(f"Captured raw video: {webm_files[0]}")
    return webm_files[0]


def mux_final_video(raw_video: Path, full_audio: Path) -> Path:
    print("\n--- Step 5: Encoding High-Quality MP4 Video with Audio Muxing ---")
    cmd = [
        "ffmpeg",
        "-y",
        "-i",
        str(raw_video),
        "-i",
        str(full_audio),
        "-c:v",
        "libx264",
        "-preset",
        "fast",
        "-crf",
        "20",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-shortest",
        "-movflags",
        "+faststart",
        str(OUTPUT_VIDEO),
    ]
    subprocess.run(cmd, check=True)
    size_mb = OUTPUT_VIDEO.stat().st_size / (1024 * 1024)
    print(f"\n=======================================================")
    print(f"SUCCESS! Demo video created: {OUTPUT_VIDEO}")
    print(f"File Size: {size_mb:.2f} MB")
    print(f"=======================================================")
    return OUTPUT_VIDEO


def main():
    print("=======================================================")
    print("AegisGraph Hackathon Demo Video Builder")
    print("=======================================================")
    try:
        tracks = generate_audio_tracks()
        full_audio = concatenate_audio(tracks)
        raw_video = record_browser_session(tracks)
        mux_final_video(raw_video, full_audio)
    finally:
        # Clean up temp artifacts
        if TEMP_DIR.exists():
            shutil.rmtree(TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
