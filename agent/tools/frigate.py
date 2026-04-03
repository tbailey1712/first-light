"""
Frigate NVR tools — queries the local Frigate instance for camera health,
recording status, and detection activity.

Frigate runs at 192.168.2.7:5000 (no auth required on the API port).
Cameras: front_camera, back_yard, garage-main, garage-side, alley
Detector: Coral TPU (inference ~10ms)

.env vars required: none (hardcoded host — Frigate is on a fixed IP)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_FRIGATE_URL = "http://192.168.2.7:5000"
_CAMERAS = ["front_camera", "back_yard", "garage-main", "garage-side", "alley"]

# Min acceptable FPS — cameras below this are considered degraded
_MIN_CAMERA_FPS = 5.0


def _get(path: str, params: Optional[dict] = None) -> dict | list:
    """GET from Frigate API. Returns parsed JSON or error dict."""
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(f"{_FRIGATE_URL}{path}", params=params or {})
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


@tool
def query_frigate_health() -> str:
    """Get Frigate NVR health: camera FPS, recording status, storage, and detector.

    Checks all five cameras (front_camera, back_yard, garage-main, garage-side, alley)
    for active capture, process FPS, and skipped frames. Flags any camera below 5 FPS
    or with a dead ffmpeg process. Reports Coral TPU inference speed, storage utilization
    on the recordings volume, and per-camera recording hours for today.

    Returns:
        JSON with per-camera health, detector status, storage, and any degraded cameras.
    """
    stats = _get("/api/stats")
    if "error" in stats:
        return json.dumps({"error": f"Frigate API unavailable: {stats['error']}"})

    cameras_raw = stats.get("cameras", {})
    detector = stats.get("detectors", {}).get("coral", {})
    service = stats.get("service", {})

    # Per-camera health
    camera_health = []
    degraded = []
    for cam, data in cameras_raw.items():
        cam_fps = data.get("camera_fps", 0)
        proc_fps = data.get("process_fps", 0)
        skipped = data.get("skipped_fps", 0)
        ffmpeg_pid = data.get("ffmpeg_pid")
        capture_pid = data.get("capture_pid")
        status = "ok"
        issues = []
        if cam_fps < _MIN_CAMERA_FPS:
            status = "degraded"
            issues.append(f"camera_fps={cam_fps:.1f} below threshold {_MIN_CAMERA_FPS}")
        if skipped > 1.0:
            status = "degraded"
            issues.append(f"skipped_fps={skipped:.1f}")
        if not ffmpeg_pid:
            status = "dead"
            issues.append("ffmpeg process missing")
        entry = {
            "camera": cam,
            "status": status,
            "camera_fps": round(cam_fps, 1),
            "process_fps": round(proc_fps, 1),
            "skipped_fps": round(skipped, 1),
            "detection_fps": round(data.get("detection_fps", 0), 1),
            "detection_enabled": data.get("detection_enabled", False),
            "ffmpeg_pid": ffmpeg_pid,
        }
        if issues:
            entry["issues"] = issues
            degraded.append(cam)
        camera_health.append(entry)

    # Storage
    recordings_storage = service.get("storage", {}).get("/media/frigate/recordings", {})
    total_kb = recordings_storage.get("total", 0)
    used_kb = recordings_storage.get("used", 0)
    free_kb = recordings_storage.get("free", 0)
    used_pct = round(used_kb / total_kb * 100, 1) if total_kb else 0

    # Per-camera recording hours today
    recording_summary = {}
    for cam in _CAMERAS:
        cam_summary = _get(f"/api/{cam}/recordings/summary")
        if isinstance(cam_summary, list) and cam_summary:
            today = cam_summary[0]  # Most recent day first
            hours_data = today.get("hours", [])
            total_secs = sum(h.get("duration", 0) for h in hours_data)
            total_motion = sum(h.get("motion", 0) for h in hours_data)
            recording_summary[cam] = {
                "date": today.get("day"),
                "recording_hours": round(total_secs / 3600, 2),
                "motion_events": total_motion,
                "hours_with_data": len(hours_data),
            }
        else:
            recording_summary[cam] = {"status": "no_data"}

    uptime_days = round(service.get("uptime", 0) / 86400, 1)

    return json.dumps({
        "overall_status": "degraded" if degraded else "ok",
        "degraded_cameras": degraded,
        "version": service.get("version"),
        "uptime_days": uptime_days,
        "detector": {
            "name": "coral",
            "inference_ms": round(detector.get("inference_speed", 0), 1),
            "status": "ok" if detector.get("pid") else "dead",
        },
        "storage_recordings": {
            "total_gb": round(total_kb / 1024, 1),
            "used_gb": round(used_kb / 1024, 1),
            "free_gb": round(free_kb / 1024, 1),
            "used_pct": used_pct,
            "mount_type": recordings_storage.get("mount_type"),
        },
        "cameras": camera_health,
        "recording_today": recording_summary,
    }, indent=2)


@tool
def query_frigate_events(hours: int = 24, camera: Optional[str] = None) -> str:
    """Get Frigate detection events for the past N hours.

    Args:
        hours: Lookback window in hours (default: 24)
        camera: Optional camera name to filter (default: all cameras)

    Returns:
        JSON with event counts per camera, top detected objects, and recent events.
    """
    import time
    after = int(time.time()) - (hours * 3600)

    params: dict = {"limit": 200, "after": after, "include_thumbnails": 0}
    if camera:
        params["cameras"] = camera

    events = _get("/api/events", params)
    if isinstance(events, dict) and "error" in events:
        return json.dumps(events)

    if not isinstance(events, list):
        return json.dumps({"error": "Unexpected response format", "raw": str(events)[:200]})

    # Aggregate by camera and object type
    by_camera: dict = {}
    by_object: dict = {}
    for ev in events:
        cam = ev.get("camera", "unknown")
        obj = ev.get("label", "unknown")
        by_camera[cam] = by_camera.get(cam, 0) + 1
        by_object[obj] = by_object.get(obj, 0) + 1

    # Recent 5 events
    recent = [
        {
            "camera": ev.get("camera"),
            "object": ev.get("label"),
            "score": round(ev.get("top_score") or 0, 2),
            "start": datetime.fromtimestamp(ev.get("start_time", 0), tz=timezone.utc).isoformat(),
            "duration_s": round((ev.get("end_time") or ev.get("start_time", 0)) - ev.get("start_time", 0), 1),
        }
        for ev in sorted(events, key=lambda e: e.get("start_time", 0), reverse=True)[:5]
    ]

    return json.dumps({
        "time_range": f"last {hours}h",
        "total_events": len(events),
        "by_camera": by_camera,
        "by_object": by_object,
        "recent_events": recent,
    }, indent=2)
