"""runtime_guard.py — interpreter-level backstop for effects the static audit can't see. (governance v2)

`mediation_audit.py` is STATIC: it reads source, so it cannot see a primitive reached by dynamic
dispatch (`getattr(os, "system")(...)`), by `eval`/`exec` of a constructed string, or through a C
extension called by name. This is the runtime complement — a PEP 578 audit hook
(`sys.addaudithook`) that fires INSIDE CPython the moment an effect actually happens, regardless of
how the call was written, and blocks it unless the current thread is inside a permitted executor
dispatch window.

The two layers compose into the answer to GOVERNANCE_MODEL.md §7.3 ("governs the mediated path
only"): the static audit fails the build on an effect written outside the executor; the runtime
guard fails the *action* on an effect reached by indirection the source didn't reveal. Neither
replaces the OS boundary (`sandbox_harness/`) — see the honest limits below.

    from runtime_guard import install, permit, RuntimeGuardBlocked
    install()                        # once, at process start — a hook cannot be removed (PEP 578)
    ...
    with permit():                   # executor.execute() opens this window around a permitted handler
        do_the_effect()              # guarded effects are allowed here, and ONLY here

Outside a `permit()` window, a guarded effect raises `RuntimeGuardBlocked` before it runs — the
audit event fires at the entry of the C implementation, so the shell command / socket / dlopen
never executes.

WHAT IT CATCHES that the static audit cannot:
  * `getattr(os, "system")("...")`, `f = subprocess.Popen; f(...)` — the event is raised by the
    implementation, so the call SHAPE in source is irrelevant.
  * a handle passed across a module boundary, or fetched from a dict of callables.
  * (with the code-loading set enabled) `exec`/`eval` of a string and dynamic `import`.

DEFAULT GUARDED SET is the high-risk surface the framework's own infrastructure never touches —
process spawn, outbound network, and native library loading — so installing the guard does not
break ordinary operation (the ledger uses `open`, not `subprocess`/`socket`). `open` and `import`
are NOT in the default set precisely because infrastructure uses them everywhere; add them via
`install(extra=...)` only in an agent process that does all its importing before `install()`.

HONEST LIMITS — a guard that oversells itself is worse than none:
  * IN-PROCESS ONLY. A native exploit that corrupts memory below CPython, or a `fork()`+`exec()`
    into a FRESH interpreter with no hook, is outside its reach. That is exactly what the OS
    boundary (`sandbox_harness/`: non-root, egress cage, seccomp/Landlock) is for. Gate necessary,
    boundary sufficient — this raises the bar, it does not seal the surface.
  * A hook cannot be un-registered (PEP 578), but it runs at the program's own privilege; code
    that can call raw syscalls or rewrite interpreter state defeats it. Defense in depth, not a jail.
  * The permit window is thread-local and reentrant: an effect on ANOTHER thread mid-window is
    still blocked, which is intended — one dispatch is one thread.
"""
from __future__ import annotations

import sys
import threading

# High-risk audit events blocked outside a permit window. These are effects the governance
# engine itself never performs, so guarding them globally does not disturb normal operation.
DEFAULT_GUARDED = frozenset({
    "os.system",
    "subprocess.Popen",
    "os.exec",            # os.exec* family raises this
    "os.spawn",           # os.spawn* family raises this
    "socket.connect",
    "socket.bind",
    "socket.getaddrinfo",
    "ctypes.dlopen",
    "ctypes.dlsym",
    "ctypes.call_function",
})

# Optional, for an agent that imports everything before install(): the code-loading surface.
CODE_LOADING = frozenset({"exec", "compile", "import"})


class RuntimeGuardBlocked(RuntimeError):
    """Raised inside a guarded effect event when no permit window is open on this thread."""


_state = threading.local()
_guarded: set = set()
_installed = False


def _permitted() -> bool:
    return getattr(_state, "depth", 0) > 0


class permit:
    """Context manager (reentrant, thread-local) that opens a window in which guarded effects run.
    The executor opens exactly one of these around a handler the gate has permitted."""
    def __enter__(self):
        _state.depth = getattr(_state, "depth", 0) + 1
        return self

    def __exit__(self, *exc):
        _state.depth = getattr(_state, "depth", 1) - 1
        return False


def _hook(event: str, args):
    # Minimal and allocation-light: membership + a thread-local int. No I/O here, or the hook
    # would recurse through its own guarded events.
    if not _guarded:
        return
    if event in _guarded and not _permitted():
        raise RuntimeGuardBlocked(f"effect {event!r} outside a permitted executor window")


def install(events=None, extra=None) -> None:
    """Install the audit hook once. `events` overrides the default guarded set; `extra` adds to it
    (e.g. `install(extra=runtime_guard.CODE_LOADING)`). Idempotent: a second call only updates the
    guarded set (the hook itself, per PEP 578, can never be removed once added)."""
    global _installed
    base = set(DEFAULT_GUARDED if events is None else events)
    if extra:
        base |= set(extra)
    _guarded.clear()
    _guarded.update(base)
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True


def guarded_events() -> set:
    return set(_guarded)


def _selftest() -> int:
    """Prove the guard blocks a dynamic-dispatch escape the static audit cannot see, allows the
    same effect inside a permit window, and leaves reads/imports alone. Returns 0 on success."""
    import os
    install(extra={"guard.test.effect"})
    fails = []

    # 1. A guarded effect reached by DYNAMIC DISPATCH is blocked outside a permit window. The
    #    command never runs, because the audit event fires before os.system executes it.
    f = getattr(os, "system")            # static audit cannot see this
    try:
        f("echo runtime_guard_should_have_blocked_this")
        fails.append("os.system via getattr was NOT blocked")
    except RuntimeGuardBlocked:
        pass

    # 2. A synthetic (side-effect-free) guarded event: blocked outside, allowed inside.
    try:
        sys.audit("guard.test.effect")
        fails.append("guarded event not blocked outside permit")
    except RuntimeGuardBlocked:
        pass
    try:
        with permit():
            sys.audit("guard.test.effect")   # must NOT raise
    except RuntimeGuardBlocked:
        fails.append("guarded event blocked INSIDE a permit window (should be allowed)")

    # 3. A non-guarded operation (a read) is never blocked, in or out of a window.
    try:
        os.getcwd()
        import json as _j  # noqa: F401
    except RuntimeGuardBlocked:
        fails.append("a read/import was blocked (default set is too broad)")

    # 4. The permit window is not sticky: after it closes, effects are blocked again.
    try:
        sys.audit("guard.test.effect")
        fails.append("permit window did not close (effect still allowed after exit)")
    except RuntimeGuardBlocked:
        pass

    if fails:
        for m in fails:
            print(f"  FAIL {m}")
        return 1
    print("  OK runtime guard: dynamic-dispatch escape blocked, permit window scopes effects")
    return 0


if __name__ == "__main__":
    sys.exit(_selftest())
