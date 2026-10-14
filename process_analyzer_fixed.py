
import os
import time
import psutil

TEST_FOLDER = os.path.normcase(
    os.path.abspath(
        os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            "RansomwareTest"
        )
    )
)


def analyze_processes():
    """
    Observe running processes without stopping, suspending,
    or modifying them.

    Returns a limited process inventory and indicates whether
    each visible process references the dedicated test folder.
    A folder reference alone is not evidence of malicious activity.
    """
    results = []

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "cmdline"]
    ):
        try:
            info = proc.info
            name = info.get("name") or "Unknown"
            executable = info.get("exe") or ""
            cmdline = info.get("cmdline") or []

            command_parts = [executable] + [
                str(part) for part in cmdline if part
            ]
            command = os.path.normcase(
                " ".join(command_parts)
            )

            references_test_folder = (
                TEST_FOLDER.casefold() in command.casefold()
            )

            results.append({
                "pid": info.get("pid"),
                "name": name,
                "executable": executable,
                "references_test_folder": references_test_folder,
                "reason": (
                    "References test folder"
                    if references_test_folder
                    else "Process inventory observation"
                ),
                "observed_at": time.strftime("%H:%M:%S"),
                "action": "Observe only"
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return results[:50]
