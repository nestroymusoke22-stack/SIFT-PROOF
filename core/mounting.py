"""
core/mounting.py — Dynamic evidence ingestion & automated mounting.

Turns whatever was passed to --image into a live, read-only directory the
parsers can walk. Three cases are auto-detected:

  CASE A  directory / pre-mounted share   → pass straight through (no mounting)
  CASE B  E01 holding a raw NTFS volume    → ewfmount, then mount offset 0
  CASE C  E01 holding a full disk + table  → ewfmount, find NTFS offset, mount

A forceful cleanup runs before every mount attempt so stale FUSE mounts and
process locks can never cause "mountpoint is not empty" failures.

Everything is best-effort and defensive: if a required forensic binary
(ewfmount/mmls/mount) is missing we raise MountError with actionable guidance
instead of crashing the investigation.
"""

import os
import re
import shutil
import subprocess

EWF_MOUNT = "/mnt/ewf"
WIN_MOUNT = "/mnt/windows_c"
E01_EXTENSIONS = ('.e01', '.ex01', '.s01', '.aff', '.raw', '.dd', '.img', '.001')
SECTOR_SIZE = 512


class MountError(Exception):
    """Raised when an image cannot be mounted (missing tools or layout issues)."""


def _run(cmd, **kw):
    """Run a command, capturing output. Never raises on non-zero exit."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _have(binary):
    return shutil.which(binary) is not None


def cleanup_mounts(win_mount=WIN_MOUNT, ewf_mount=EWF_MOUNT):
    """
    Forcefully release any prior mounts/locks before a new mount attempt.

    Lazy + forceful umount and fuser -k guarantee a clean mountpoint so FUSE
    cannot report "mountpoint is not empty".
    """
    for mnt in (win_mount, ewf_mount):
        if _have('fuser'):
            _run(['sudo', 'fuser', '-k', mnt])
        _run(['sudo', 'umount', '-fl', mnt])
    return True


def _detect_ntfs_offset(ewf_image):
    """
    CASE B vs C discriminator.

    Returns the NTFS partition byte offset:
      - 0  when the image is a raw NTFS volume (no partition table)
      - >0 when a partition table places NTFS further into the disk

    Strategy: read the boot sector signature; if it is already NTFS, offset 0.
    Otherwise parse `mmls` (preferred) or `parted` for the first NTFS slot.
    """
    # Raw NTFS volume? The OEM ID "NTFS" sits at byte offset 3 of sector 0.
    try:
        with open(ewf_image, 'rb') as f:
            boot = f.read(512)
        if boot[3:7] == b'NTFS':
            print("[MOUNT] Raw NTFS boot sector detected — forcing offset 0 (Case B)")
            return 0
    except Exception as e:
        print(f"[MOUNT] Boot-sector probe failed ({e}); falling back to mmls")

    # Partitioned disk → find the NTFS partition's starting sector.
    if _have('mmls'):
        res = _run(['mmls', ewf_image])
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if re.search(r'NTFS|Win', line, re.IGNORECASE):
                    m = re.search(r'^\s*\d+:\s+\S+\s+(\d+)', line)
                    if m:
                        start = int(m.group(1))
                        print(f"[MOUNT] mmls found NTFS at sector {start} (Case C)")
                        return start * SECTOR_SIZE

    if _have('parted'):
        res = _run(['parted', '-sm', ewf_image, 'unit', 'B', 'print'])
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if re.search(r'ntfs', line, re.IGNORECASE):
                    m = re.match(r'\s*\d+:(\d+)B:', line)
                    if m:
                        start = int(m.group(1))
                        print(f"[MOUNT] parted found NTFS at byte {start} (Case C)")
                        return start

    # Could not determine a partition offset → assume raw NTFS at 0.
    print("[MOUNT] No partition table parsed — defaulting to offset 0")
    return 0


def _mount_e01(image_path, ewf_mount=EWF_MOUNT, win_mount=WIN_MOUNT):
    """Mount an E01 (Case B or C) and return the Windows mount directory."""
    if not _have('ewfmount'):
        raise MountError(
            "ewfmount not installed — cannot mount an E01 here. Either run on a "
            "SIFT workstation, or pre-mount the volume and pass the directory "
            "path to --image (Case A)."
        )
    if not _have('mount'):
        raise MountError("`mount` unavailable — cannot mount NTFS volume.")

    _run(['sudo', 'mkdir', '-p', ewf_mount, win_mount])
    cleanup_mounts(win_mount, ewf_mount)

    print(f"[MOUNT] ewfmount {image_path} → {ewf_mount}")
    res = _run(['sudo', 'ewfmount', image_path, ewf_mount])
    if res.returncode != 0:
        raise MountError(f"ewfmount failed: {res.stderr.strip()}")

    ewf_image = os.path.join(ewf_mount, 'ewf1')
    if not os.path.exists(ewf_image):
        raise MountError(f"ewfmount produced no {ewf_image}")

    offset = _detect_ntfs_offset(ewf_image)
    mount_opts = f"ro,noatime,loop,offset={offset}" if offset else "ro,noatime,loop"

    print(f"[MOUNT] mount -t ntfs-3g -o {mount_opts} {ewf_image} → {win_mount}")
    res = _run(['sudo', 'mount', '-t', 'ntfs-3g', '-o', mount_opts,
                ewf_image, win_mount])
    if res.returncode != 0:
        raise MountError(
            f"ntfs-3g mount failed at offset {offset}: {res.stderr.strip()}")

    if not os.path.isdir(os.path.join(win_mount, 'Windows')) and \
       not os.path.isdir(os.path.join(win_mount, 'WINDOWS')):
        print(f"[MOUNT] WARNING: no Windows/ directory under {win_mount} "
              "— parsers will still try, but check the offset.")
    return win_mount


def prepare_evidence(image_path, ewf_mount=EWF_MOUNT, win_mount=WIN_MOUNT):
    """
    Resolve --image into a directory the parsers can walk.

    Returns (resolved_path, was_mounted):
      - Directory input            → (image_path, False)        [Case A]
      - Memory dump (.raw/.mem/…)  → (image_path, False)  handled by volatility
      - E01/disk image             → (mount_dir,  True)         [Case B/C]
    """
    if not os.path.exists(image_path):
        raise MountError(f"Image path does not exist: {image_path}")

    # CASE A — already a directory (shared folder or pre-mounted volume)
    if os.path.isdir(image_path):
        print(f"[MOUNT] Directory input detected — passthrough (Case A): {image_path}")
        return image_path, False

    ext = os.path.splitext(image_path)[1].lower()

    # Memory dumps are consumed directly by Volatility, not mounted.
    if ext in ('.mem', '.dmp', '.vmem', '.lime'):
        return image_path, False

    # CASE B / C — disk/E01 image file → mount it
    if ext in E01_EXTENSIONS:
        return _mount_e01(image_path, ewf_mount, win_mount), True

    # Unknown file type: let the caller try it as-is rather than guessing.
    print(f"[MOUNT] Unrecognized image extension '{ext}' — passing through as-is")
    return image_path, False


def teardown(win_mount=WIN_MOUNT, ewf_mount=EWF_MOUNT):
    """Unmount everything we mounted. Safe to call even if nothing is mounted."""
    cleanup_mounts(win_mount, ewf_mount)