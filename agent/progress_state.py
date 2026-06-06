
import json
import os
from datetime import datetime

PROGRESS_PATH = os.path.join(os.path.dirname(__file__), 'progress.json')


def save_progress(iteration, findings, coverage, pending_goals,
                  image_path="", case_type=""):
    """Call this after EVERY iteration in agent_loop.py."""
    state = {
        "saved_at": datetime.utcnow().isoformat(),
        "image_path": image_path,
        "case_type": case_type,
        "iteration": iteration,
        "findings": findings,         # list of finding_ids confirmed so far
        "coverage": coverage,         # dict from get_coverage_status()
        "pending_goals": pending_goals,
        "status": "in_progress"
    }
    with open(PROGRESS_PATH, 'w') as f:
        json.dump(state, f, indent=2, default=str)


def load_progress(image_path=None):
    """
    Returns prior state dict if a matching in-progress run exists.
    Returns None if no prior state, prior run was complete, or image differs.
    """
    if not os.path.exists(PROGRESS_PATH):
        return None
    try:
        with open(PROGRESS_PATH) as f:
            state = json.load(f)

        if state.get("status") == "complete":
            return None   # Previous run finished cleanly — start fresh

        if image_path and state.get("image_path") != image_path:
            return None   # Different image — start fresh

        return state
    except (json.JSONDecodeError, KeyError):
        return None       # Corrupted file — start fresh


def mark_complete():
    """Mark the current investigation as done."""
    if not os.path.exists(PROGRESS_PATH):
        return
    try:
        with open(PROGRESS_PATH) as f:
            state = json.load(f)
        state["status"] = "complete"
        state["completed_at"] = datetime.utcnow().isoformat()
        with open(PROGRESS_PATH, 'w') as f:
            json.dump(state, f, indent=2, default=str)
    except Exception:
        pass


def clear_progress():
    """Force a fresh start by deleting the checkpoint."""
    if os.path.exists(PROGRESS_PATH):
        os.remove(PROGRESS_PATH)
        print("[PROGRESS] Checkpoint cleared — fresh investigation starting.")