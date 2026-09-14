"""mediation_audit.py — static proof that every effect goes through the executor waist. (governance v2)

The completeness obligation of GOVERNANCE_MODEL.md §7.3, mechanised. `executor.py` makes the
mediated door the ONLY door by convention; this makes the convention checkable. It walks the AST
of a set of AGENT-REACHABLE modules and reports any raw effect primitive that appears OUTSIDE the
executor — an un-mediated door someone added. Wire it into CI and a new bypass fails the build.

    from mediation_audit import audit
    violations = audit(["youragent/tools.py", "youragent/loop.py"])
    assert not violations, violations

    # or, in CI:
    python mediation_audit.py youragent/*.py        # exits 1 and prints each violation

SCOPE IS EXPLICIT, AND IT MATTERS. Pass the modules the AGENT LOOP can reach. Completeness is a
property of the agent surface — not of the whole repo. The governance engine itself (kernel,
ledger, corrigibility, governance_operator), offline tooling (build_bundle, the red-team
harnesses), and the tests are the trusted base: they legitimately use file and network
primitives and are NOT agent effectors. Auditing them would drown the real signal. Only the
integrator knows which modules the agent can actually run, so only the integrator can set scope.

WHAT IT CATCHES (raw effect sinks): process exec (os.system/popen/exec*/spawn*, subprocess.*),
network (socket, http.client, urllib.request.urlopen, requests.*, httpx.*), filesystem writes and
deletes (open(...) in a write/append/exclusive mode, os.remove/unlink/rename/replace/truncate,
shutil.rmtree/move/copy*). Reads (open default or 'r', os.path.*, os.getcwd) are NOT flagged.

WHAT IT CANNOT CATCH — stated, because a checker that oversells itself is worse than none:
dynamic dispatch (getattr(os, name)()), C extensions / FFI, a primitive reached via eval, and any
sink not on the list below. It raises the cost of an accidental bypass to "you had to work around
a red build"; it is not a capability proof. The OS boundary (sandbox_harness/) is what contains
the sink that never enters Python's call graph. Gate necessary, boundary sufficient.
"""
from __future__ import annotations

import ast
import os
import sys

# Exact dotted callables that are effect sinks.
_SINK_FULL = {
    "os.system", "os.popen", "os.remove", "os.unlink", "os.rename", "os.replace",
    "os.removedirs", "os.rmdir", "os.truncate", "os.posix_spawn", "os.posix_spawnp",
    "socket.socket", "socket.create_connection", "socket.create_server",
    "urllib.request.urlopen", "shutil.rmtree", "shutil.move", "shutil.copy",
    "shutil.copy2", "shutil.copyfile", "shutil.copytree",
}
# Module prefixes where ANY attribute call is a sink (the whole surface is effectful).
_SINK_PREFIX = ("subprocess.", "requests.", "httpx.", "http.client.")
# os.exec* / os.spawn* families (prefix match under the os module).
_OS_CALL_PREFIXES = ("exec", "spawn")
# open() modes that WRITE. A read ('r' or default) is allowed.
_WRITE_CHARS = set("wax+")


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a call target: os.path.join -> 'os.path.join', run -> 'run'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.aliases: dict = {}      # local name -> module (import x as y ; import a.b)
        self.fromimports: dict = {}  # local name -> full dotted origin (from a import b as c)
        self.violations: list = []

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.level == 0:
            for a in node.names:
                self.fromimports[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def _resolve(self, dotted: str) -> str:
        """Rewrite a call's dotted target through the import maps to a canonical origin."""
        head, _, rest = dotted.partition(".")
        if dotted in self.fromimports:            # `from subprocess import run` -> `run`
            return self.fromimports[dotted]
        if head in self.fromimports and not rest:
            return self.fromimports[head]
        if head in self.aliases:                  # `import urllib.request as U` -> U.urlopen
            base = self.aliases[head]
            return f"{base}.{rest}" if rest else base
        return dotted

    def _flag(self, node, sink):
        self.violations.append({"line": node.lineno, "sink": sink})

    def visit_Call(self, node):
        target = self._resolve(_dotted(node.func))
        # open(path, "w") — inspect the mode
        if target in ("open", "io.open"):
            mode = ""
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    mode = kw.value.value
            # default (no mode) is read; unknown/dynamic mode -> fail-closed and flag
            if len(node.args) >= 2 or any(k.arg == "mode" for k in node.keywords):
                if (not mode) or (set(mode) & _WRITE_CHARS):
                    self._flag(node, f"open({mode or '?'})")
        elif target in _SINK_FULL:
            self._flag(node, target)
        elif target.startswith(_SINK_PREFIX):
            self._flag(node, target)
        elif target.startswith("os.") and any(
                target[3:].startswith(p) for p in _OS_CALL_PREFIXES):
            self._flag(node, target)
        self.generic_visit(node)


def audit(paths, executor_module: str = "executor.py") -> list:
    """Return a list of violations across `paths`, excluding the executor module itself.

    Each violation: {file, line, sink}. An empty list means every effect in the audited scope
    routes through the executor. A file that cannot be parsed is itself a violation (fail-closed:
    an unauditable agent module is not a safe one)."""
    exe = os.path.basename(executor_module)
    out = []
    for path in paths:
        if os.path.basename(path) == exe:
            continue
        try:
            src = open(path, encoding="utf-8").read()
            tree = ast.parse(src, filename=path)
        except Exception as e:
            out.append({"file": path, "line": 0, "sink": f"unparseable ({type(e).__name__})"})
            continue
        v = _Visitor()
        v.visit(tree)
        for hit in v.violations:
            out.append({"file": path, "line": hit["line"], "sink": hit["sink"]})
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print("usage: python mediation_audit.py <agent-reachable .py files...>")
        print("       fails (exit 1) if any effect primitive is reachable outside executor.py")
        sys.exit(2)
    violations = audit(args)
    if violations:
        print(f"MEDIATION BYPASS — {len(violations)} raw effect primitive(s) outside the executor:")
        for x in violations:
            print(f"  {x['file']}:{x['line']}  {x['sink']}")
        sys.exit(1)
    print(f"OK — {len(args)} file(s) audited, every effect routes through the executor waist")
    sys.exit(0)
