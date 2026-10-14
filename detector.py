
import os
import time
import threading
import logging
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

HOME = os.path.abspath(os.path.expanduser("~"))

# Monitor selected user folders, plus the dedicated test folder.
FOLDER_NAMES = [
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Videos",
    "Music",
    os.path.join("Desktop", "RansomwareTest"),
]

WATCH_FOLDERS = list(dict.fromkeys(
    os.path.abspath(os.path.join(HOME, name))
    for name in FOLDER_NAMES
))

events = deque(maxlen=1000)
lock = threading.Lock()
observer = None


class SafeFileHandler(FileSystemEventHandler):
    """Record file activity without modifying files."""

    def record(self, event_type, path):
        item = {
            "timestamp": time.time(),
            "time": time.strftime("%H:%M:%S"),
            "type": event_type,
            "file": os.path.basename(path),
            "path": os.path.abspath(path),
        }

        with lock:
            events.append(item)

        logger.info(
            "[FILE EVENT] %s: %s",
            event_type,
            item["path"],
        )

    def on_created(self, event):
        if not event.is_directory:
            self.record("Created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.record("Modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.record("Renamed", event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.record("Deleted", event.src_path)


def start_watcher():
    global observer

    if observer is not None and observer.is_alive():
        return True

    active_folders = [
        folder for folder in WATCH_FOLDERS
        if os.path.isdir(folder)
    ]

    if not active_folders:
        logger.error("No valid folders are available to monitor.")
        return False

    new_observer = Observer()

    try:
        handler = SafeFileHandler()

        for folder in active_folders:
            new_observer.schedule(
                handler,
                folder,
                recursive=True,
            )
            logger.info("Monitoring folder: %s", folder)

        new_observer.start()
        observer = new_observer
        time.sleep(0.2)

        if not observer.is_alive():
            logger.error("Filesystem observer failed to start.")
            return False

        logger.info(
            "Watcher started for %s folder(s).",
            len(active_folders),
        )
        return True

    except Exception:
        logger.exception("Could not start filesystem watcher")

        try:
            new_observer.stop()
            if new_observer.is_alive():
                new_observer.join(timeout=5)
        except Exception:
            logger.exception("Error cleaning up watcher")

        observer = None
        return False


def stop_watcher():
    global observer

    current = observer

    if current is not None:
        current.stop()
        current.join(timeout=5)

        if current.is_alive():
            logger.error("Watcher did not stop within 5 seconds.")
            return False

        observer = None

    return True


def get_events():
    with lock:
        return list(events)
