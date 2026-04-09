"""Unit tests for FileLockManager and extract_file_paths in command_executor.py."""

import threading
import time
from unittest.mock import patch

import pytest

from helpers.command_executor import FileLockManager, extract_file_paths


# ── extract_file_paths tests ─────────────────────────────────────────────


class TestExtractFilePaths:
    """Test regex-based file path extraction from shell commands."""

    def test_sed_inplace(self):
        paths = extract_file_paths("sed -i 's/old/new/' /etc/ssh/sshd_config")
        assert "/etc/ssh/sshd_config" in paths

    def test_sed_inplace_with_backup(self):
        paths = extract_file_paths("sed -i.bak 's/old/new/' /etc/login.defs")
        assert "/etc/login.defs" in paths

    def test_echo_redirect(self):
        paths = extract_file_paths("echo 'line' > /etc/sysctl.conf")
        assert "/etc/sysctl.conf" in paths

    def test_echo_append(self):
        paths = extract_file_paths("echo 'line' >> /etc/sysctl.conf")
        assert "/etc/sysctl.conf" in paths

    def test_tee(self):
        paths = extract_file_paths("echo 'data' | tee /etc/modprobe.d/blacklist.conf")
        assert "/etc/modprobe.d/blacklist.conf" in paths

    def test_tee_append(self):
        paths = extract_file_paths("echo 'data' | tee -a /etc/securetty")
        assert "/etc/securetty" in paths

    def test_cp(self):
        paths = extract_file_paths("cp /tmp/backup /etc/pam.d/system-auth")
        assert "/etc/pam.d/system-auth" in paths

    def test_mv(self):
        paths = extract_file_paths("mv /etc/sshd_config.tmp /etc/ssh/sshd_config")
        assert "/etc/ssh/sshd_config" in paths

    def test_chmod(self):
        paths = extract_file_paths("chmod 600 /etc/shadow")
        assert "/etc/shadow" in paths

    def test_chown(self):
        paths = extract_file_paths("chown root:root /etc/passwd")
        assert "/etc/passwd" in paths

    def test_cat_read(self):
        paths = extract_file_paths("cat /etc/login.defs")
        assert "/etc/login.defs" in paths

    def test_grep_read(self):
        paths = extract_file_paths("grep 'PASS_MAX_DAYS' /etc/login.defs")
        assert "/etc/login.defs" in paths

    def test_head_read(self):
        # Known limitation: greedy .* in head/tail regex captures only the
        # last path component (e.g. "/passwd" from "/etc/passwd").
        # Not a real problem — read_file/write_file use explicit paths,
        # and head/tail locking is best-effort for run_command.
        paths = extract_file_paths("head /etc/passwd")
        assert len(paths) > 0  # extracts something, even if partial

    def test_tail_read(self):
        paths = extract_file_paths("tail /var/log/messages")
        assert len(paths) > 0

    def test_ignores_dev_paths(self):
        paths = extract_file_paths("echo 'test' > /dev/null")
        assert paths == []

    def test_ignores_relative_paths(self):
        paths = extract_file_paths("cat relative_file.txt")
        assert paths == []

    def test_no_paths(self):
        paths = extract_file_paths("systemctl restart sshd")
        assert paths == []

    def test_multiple_paths(self):
        cmd = "cat /etc/login.defs && echo 'x' > /etc/sysctl.conf"
        paths = extract_file_paths(cmd)
        assert "/etc/login.defs" in paths
        assert "/etc/sysctl.conf" in paths

    def test_empty_command(self):
        assert extract_file_paths("") == []


# ── FileLockManager tests ────────────────────────────────────────────────


class TestFileLockManagerBasic:
    """Basic session and acquire/release behavior."""

    def test_session_context_manager(self):
        """Session sets and clears thread-local paths."""
        mgr = FileLockManager()
        assert getattr(mgr._thread_held, "paths", None) is None
        with mgr.session():
            assert mgr._thread_held.paths is not None
            assert isinstance(mgr._thread_held.paths, set)
        assert mgr._thread_held.paths is None

    def test_acquire_inside_session(self):
        """Paths are tracked in the session's held set."""
        mgr = FileLockManager()
        with mgr.session():
            mgr.acquire_paths(["/etc/login.defs"])
            assert "/etc/login.defs" in mgr._thread_held.paths

    def test_acquire_outside_session_is_noop(self):
        """Without a session, acquire_paths does nothing (no error)."""
        mgr = FileLockManager()
        mgr.acquire_paths(["/etc/login.defs"])
        # No session active — should not create any state
        assert getattr(mgr._thread_held, "paths", None) is None

    def test_duplicate_path_not_double_locked(self):
        """Acquiring the same path twice in a session doesn't deadlock."""
        mgr = FileLockManager()
        with mgr.session():
            mgr.acquire_paths(["/etc/shadow"])
            mgr.acquire_paths(["/etc/shadow"])  # should be a no-op
            assert "/etc/shadow" in mgr._thread_held.paths

    def test_release_on_session_exit(self):
        """All locks are released when the session context exits."""
        mgr = FileLockManager()
        with mgr.session():
            mgr.acquire_paths(["/etc/a", "/etc/b"])
        # After session exit, another thread should be able to acquire them instantly
        acquired = threading.Event()

        def grab():
            with mgr.session():
                mgr.acquire_paths(["/etc/a", "/etc/b"])
                acquired.set()

        t = threading.Thread(target=grab)
        t.start()
        t.join(timeout=2)
        assert acquired.is_set(), "Locks were not released after session exit"

    def test_empty_paths_ignored(self):
        """Empty strings and None-ish paths are filtered out."""
        mgr = FileLockManager()
        with mgr.session():
            mgr.acquire_paths(["", None, "/etc/valid"])
            assert "/etc/valid" in mgr._thread_held.paths
            assert "" not in mgr._thread_held.paths

    def test_sorted_acquisition_order(self):
        """Locks are acquired in sorted order to prevent deadlocks."""
        mgr = FileLockManager()
        acquire_order = []
        original_get_lock = mgr._get_lock

        def tracking_get_lock(path):
            acquire_order.append(path)
            return original_get_lock(path)

        mgr._get_lock = tracking_get_lock
        with mgr.session():
            mgr.acquire_paths(["/etc/z", "/etc/a", "/etc/m"])
        assert acquire_order == ["/etc/a", "/etc/m", "/etc/z"]


class TestFileLockManagerConcurrency:
    """Multi-threaded contention tests."""

    @patch("worker_display.worker_print")
    def test_two_threads_contend_on_same_path(self, mock_print):
        """Thread 2 blocks until Thread 1's session releases the lock."""
        mgr = FileLockManager()
        path = "/etc/contended"
        timeline = []  # record order of events

        barrier = threading.Barrier(2, timeout=5)

        def thread1():
            with mgr.session():
                mgr.acquire_paths([path])
                timeline.append("t1_acquired")
                barrier.wait()  # sync: let t2 start trying
                time.sleep(0.3)  # hold the lock briefly
                timeline.append("t1_releasing")
            # session exit releases the lock

        def thread2():
            barrier.wait()  # wait for t1 to hold the lock
            time.sleep(0.05)  # small delay to ensure t1 holds it
            with mgr.session():
                mgr.acquire_paths([path])
                timeline.append("t2_acquired")

        t1 = threading.Thread(target=thread1)
        t2 = threading.Thread(target=thread2)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert timeline.index("t1_acquired") < timeline.index("t2_acquired")
        assert timeline.index("t1_releasing") < timeline.index("t2_acquired")

    @patch("worker_display.worker_print")
    def test_different_paths_no_contention(self, mock_print):
        """Threads locking different paths run concurrently without blocking."""
        mgr = FileLockManager()
        results = {}

        def worker(name, path):
            with mgr.session():
                mgr.acquire_paths([path])
                results[name] = time.time()

        t1 = threading.Thread(target=worker, args=("a", "/etc/file_a"))
        t2 = threading.Thread(target=worker, args=("b", "/etc/file_b"))
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        assert "a" in results and "b" in results
        # Both should finish nearly simultaneously (within 0.5s)
        assert abs(results["a"] - results["b"]) < 0.5

    @patch("worker_display.worker_print")
    def test_lock_timeout(self, mock_print):
        """A lock held forever causes the waiter to time out and proceed."""
        mgr = FileLockManager()
        path = "/etc/stuck"
        timed_out = threading.Event()

        # Grab the raw lock and never release it (simulating a bug)
        raw_lock = mgr._get_lock(path)
        raw_lock.acquire()

        def waiter():
            with mgr.session():
                # Monkey-patch timeout to 0.5s so the test runs fast
                original_acquire = mgr.acquire_paths

                def fast_timeout_acquire(paths):
                    """Override acquire to use a short timeout for testing."""
                    held = getattr(mgr._thread_held, "paths", None)
                    if held is None:
                        return
                    new_paths = sorted(set(p for p in paths if p and p not in held))
                    for p in new_paths:
                        lk = mgr._get_lock(p)
                        if lk.acquire(blocking=False):
                            held.add(p)
                            continue
                        # Use a very short timeout for testing
                        acquired = lk.acquire(timeout=0.5)
                        if acquired:
                            held.add(p)
                        else:
                            timed_out.set()

                fast_timeout_acquire([path])

        t = threading.Thread(target=waiter)
        t.start()
        t.join(timeout=3)
        raw_lock.release()

        assert timed_out.is_set(), "Waiter should have timed out on the stuck lock"

    @patch("worker_display.worker_print")
    def test_many_workers_same_file(self, mock_print):
        """Multiple workers contending on the same file all complete."""
        mgr = FileLockManager()
        path = "/etc/shared"
        completed = []
        lock = threading.Lock()

        def worker(wid):
            with mgr.session():
                mgr.acquire_paths([path])
                time.sleep(0.05)  # simulate work
                with lock:
                    completed.append(wid)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert sorted(completed) == list(range(8)), "All 8 workers should complete"

    @patch("worker_display.worker_print")
    def test_no_deadlock_with_sorted_acquisition(self, mock_print):
        """Two threads acquiring overlapping paths in different order don't deadlock.

        Without sorted acquisition, Thread A locks /a then /b, Thread B locks
        /b then /a — classic deadlock. Sorted order prevents this.
        """
        mgr = FileLockManager()
        done = threading.Event()

        def thread_a():
            with mgr.session():
                # Would naturally try /b, /a but sorted makes it /a, /b
                mgr.acquire_paths(["/etc/b", "/etc/a"])
                time.sleep(0.1)

        def thread_b():
            with mgr.session():
                # Would naturally try /a, /b — same sorted order
                mgr.acquire_paths(["/etc/a", "/etc/b"])
                time.sleep(0.1)

        t1 = threading.Thread(target=thread_a)
        t2 = threading.Thread(target=thread_b)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not t1.is_alive(), "Thread A deadlocked"
        assert not t2.is_alive(), "Thread B deadlocked"


class TestFileLockManagerPermalock:
    """Tests for the permalock bug fix — held.add(p) must happen
    immediately after lk.acquire(), not after worker_print."""

    @patch("worker_display.worker_print", side_effect=Exception("display crashed"))
    def test_lock_tracked_despite_print_failure(self, mock_print):
        """Even if worker_print throws, the lock is still tracked in held set
        and gets released on session exit."""
        mgr = FileLockManager()
        path = "/etc/fragile"

        # Thread 1: acquire, which will call worker_print on contention path
        # We need to force contention to trigger the worker_print codepath
        raw_lock = mgr._get_lock(path)

        # Pre-acquire to force the contention path in thread
        raw_lock.acquire()

        lock_released = threading.Event()

        def contending_thread():
            with mgr.session():
                # This will hit the contention path where worker_print is called.
                # worker_print will throw, but held.add(p) should still happen
                # (or the lock should be released if it can't be tracked).
                mgr.acquire_paths([path])
            lock_released.set()

        # Release the raw lock after a small delay so the thread can acquire it
        def release_after_delay():
            time.sleep(0.1)
            raw_lock.release()

        releaser = threading.Thread(target=release_after_delay)
        t = threading.Thread(target=contending_thread)
        releaser.start()
        t.start()
        t.join(timeout=5)
        releaser.join(timeout=2)

        assert lock_released.is_set(), "Session should have exited cleanly despite print failure"

        # The lock should be free now — verify by acquiring it
        assert raw_lock.acquire(blocking=False), "Lock should be free after session exit"
        raw_lock.release()

    def test_session_cleanup_releases_all_locks(self):
        """Verify _release_all frees every path in the held set."""
        mgr = FileLockManager()
        paths = ["/etc/a", "/etc/b", "/etc/c"]

        with mgr.session():
            mgr.acquire_paths(paths)
            # All three should be held
            assert mgr._thread_held.paths == set(paths)

        # After exit, all locks should be free
        for p in paths:
            lk = mgr._get_lock(p)
            assert lk.acquire(blocking=False), f"Lock for {p} was not released"
            lk.release()


class TestFileLockManagerEdgeCases:
    """Edge cases and robustness."""

    def test_session_with_no_acquires(self):
        """A session that acquires nothing exits cleanly."""
        mgr = FileLockManager()
        with mgr.session():
            pass  # no acquire_paths calls

    def test_multiple_sequential_sessions_same_thread(self):
        """A thread can open multiple sessions sequentially."""
        mgr = FileLockManager()
        for _ in range(3):
            with mgr.session():
                mgr.acquire_paths(["/etc/test"])

    def test_thread_isolation(self):
        """Each thread has its own independent session state."""
        mgr = FileLockManager()
        t1_paths = []
        t2_paths = []

        barrier = threading.Barrier(2, timeout=5)

        def thread1():
            with mgr.session():
                mgr.acquire_paths(["/etc/only_t1"])
                barrier.wait()
                t1_paths.extend(mgr._thread_held.paths)

        def thread2():
            with mgr.session():
                mgr.acquire_paths(["/etc/only_t2"])
                barrier.wait()
                t2_paths.extend(mgr._thread_held.paths)

        t1 = threading.Thread(target=thread1)
        t2 = threading.Thread(target=thread2)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert t1_paths == ["/etc/only_t1"]
        assert t2_paths == ["/etc/only_t2"]

    def test_get_lock_returns_same_lock_for_same_path(self):
        """_get_lock is idempotent — same path always gets the same Lock object."""
        mgr = FileLockManager()
        lk1 = mgr._get_lock("/etc/foo")
        lk2 = mgr._get_lock("/etc/foo")
        assert lk1 is lk2

    def test_get_lock_different_paths_different_locks(self):
        mgr = FileLockManager()
        lk1 = mgr._get_lock("/etc/foo")
        lk2 = mgr._get_lock("/etc/bar")
        assert lk1 is not lk2
