"""Read tool descriptions from source, without running anything (PROTOCOL.md,
"Extraction: static first, no third-party code is run").

Covered:
  TypeScript SDK   server.tool(name, description, ...)
                   server.registerTool(name, { description: ... }, ...)
  Python           @mcp.tool() on a function (FastMCP): the docstring, or a
                   literal description= in the decorator
                   Tool(name=..., description=...)

A name or description that is not a plain string in the source (a variable, a
template with ${...}, a function call) is recorded as dynamic: "not statically
extractable", counted and left out of the rates.

Each tool is a dict: {"name", "description", "kind", "form"}, where kind is
"static" or "dynamic". For a dynamic tool the name or description may be None.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")
PY_SUFFIXES = (".py",)
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", "site-packages", ".next", "coverage"}
MAX_FILE_BYTES = 1_000_000


# --- TypeScript and JavaScript -------------------------------------------------

def _mask_comments(src: str) -> str:
    """Replace comments with spaces, leaving strings alone, so positions hold."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"`":
            j = _skip_string(src, i)
            out.append(src[i:j])
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _skip_string(src: str, i: int) -> int:
    """Index just past the string literal that starts at i."""
    quote, j, n = src[i], i + 1, len(src)
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if quote == "`" and src.startswith("${", j):
            depth, j = 1, j + 2
            while j < n and depth:
                if src[j] in "'\"`":
                    j = _skip_string(src, j)
                    continue
                depth += src[j] == "{"
                depth -= src[j] == "}"
                j += 1
            continue
        if src[j] == quote:
            return j + 1
        if quote != "`" and src[j] == "\n":
            return j
        j += 1
    return n


def _split_args(src: str, start: int) -> list[str] | None:
    """The top-level arguments of the call whose '(' is at start, or None if
    the call does not close."""
    args, depth, j, last, n = [], 0, start, start + 1, len(src)
    while j < n:
        c = src[j]
        if c in "'\"`":
            j = _skip_string(src, j)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                tail = src[last:j].strip()
                if tail or args:
                    args.append(tail)
                return args
        elif c == "," and depth == 1:
            args.append(src[last:j].strip())
            last = j + 1
        j += 1
    return None


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "\n": ""}


def _literal(expr: str) -> str | None:
    """The value of a string expression made only of literals joined by +, or
    None if anything else is in it."""
    expr, parts, i, n = expr.strip(), [], 0, len(expr.strip())
    if not expr:
        return None
    while i < n:
        if expr[i] not in "'\"`":
            return None
        j = _skip_string(expr, i)
        body, quote = expr[i + 1:j - 1], expr[i]
        if j > n or j - 1 <= i or expr[j - 1] != quote:
            return None
        if quote == "`" and re.search(r"(?<!\\)\$\{", body):
            return None
        parts.append(re.sub(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\s\S])", _unescape, body))
        i = j
        m = re.match(r"\s*\+\s*", expr[i:])
        if m:
            i += m.end()
            if i >= n:
                return None
        elif expr[i:].strip():
            return None
        else:
            break
    return "".join(parts)


def _unescape(m: re.Match) -> str:
    s = m.group(1)
    if s[0] == "u":
        return chr(int(s[2:-1] if s[1] == "{" else s[1:], 16))
    if s[0] == "x" and len(s) == 3:
        return chr(int(s[1:], 16))
    return _ESCAPES.get(s, s)


def _object_value(obj: str, key: str) -> str | None:
    """The source of a top-level property's value in an object literal, or
    None if the object has no such key."""
    obj = obj.strip()
    if not (obj.startswith("{") and obj.endswith("}")):
        return None
    for prop in _split_args("(" + obj[1:-1] + ")", 0) or []:
        m = re.match(r"""\s*(?:(['"])(?P<q>[^'"]+)\1|(?P<k>[A-Za-z_$][\w$]*))\s*:""", prop)
        if m and (m.group("q") or m.group("k")) == key:
            return prop[m.end():].strip()
    return None


_TS_CALL = re.compile(r"\.\s*(tool|registerTool)\s*\(")


def extract_typescript(src: str) -> list[dict]:
    src = _mask_comments(src)
    tools = []
    for m in _TS_CALL.finditer(src):
        args = _split_args(src, m.end() - 1)
        if not args:
            continue
        form = "ts." + m.group(1)
        name = _literal(args[0])
        if m.group(1) == "tool":
            # tool(name, description?, schema?, handler): the description is the
            # second argument only when that argument is a string.
            second = args[1] if len(args) > 1 else ""
            if second[:1] in ("'", '"', "`"):
                description, dynamic = _literal(second), _literal(second) is None
            elif re.match(r"[A-Za-z_$][\w$.]*\s*$", second) and len(args) > 2:
                description, dynamic = None, True      # a variable holds it
            else:
                description, dynamic = "", False       # no description given
        else:
            value = _object_value(args[1], "description") if len(args) > 1 else None
            if len(args) > 1 and not args[1].strip().startswith("{"):
                description, dynamic = None, True      # the config is a variable
            elif value is None:
                description, dynamic = "", False
            else:
                description, dynamic = _literal(value), _literal(value) is None
        dynamic = dynamic or name is None
        tools.append({"name": name, "description": None if dynamic and description is None else description,
                      "kind": "dynamic" if dynamic else "static", "form": form})
    return tools


# --- Python ----------------------------------------------------------------------

def _py_literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _py_literal(node.left), _py_literal(node.right)
        return None if left is None or right is None else left + right
    return None


def _is_tool_decorator(dec: ast.AST) -> ast.Call | bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    named = (isinstance(target, ast.Attribute) and target.attr == "tool") or (isinstance(target, ast.Name) and target.id == "tool")
    return (dec if isinstance(dec, ast.Call) else True) if named else False


def extract_python(src: str) -> list[dict] | None:
    """Tools in one Python file, or None if the file does not parse."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError, RecursionError):
        return None
    tools = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                hit = _is_tool_decorator(dec)
                if not hit:
                    continue
                kwargs = {k.arg: k.value for k in hit.keywords} if isinstance(hit, ast.Call) else {}
                name = _py_literal(kwargs["name"]) if "name" in kwargs else node.name
                if "description" in kwargs:
                    description = _py_literal(kwargs["description"])
                else:
                    description = ast.get_docstring(node) or ""
                dynamic = name is None or description is None
                tools.append({"name": name, "description": description, "kind": "dynamic" if dynamic else "static", "form": "py.decorator"})
                break
        elif isinstance(node, ast.Call):
            target = node.func
            if (isinstance(target, ast.Name) and target.id == "Tool") or (isinstance(target, ast.Attribute) and target.attr == "Tool"):
                kwargs = {k.arg: k.value for k in node.keywords if k.arg}
                if "name" not in kwargs:
                    continue
                name = _py_literal(kwargs["name"])
                description = _py_literal(kwargs["description"]) if "description" in kwargs else ""
                dynamic = name is None or description is None
                tools.append({"name": name, "description": description, "kind": "dynamic" if dynamic else "static", "form": "py.Tool"})
    return tools


# --- A repository checked out on disk --------------------------------------------

def extract_repository(root: str | Path) -> dict:
    """Every tool found under root, with what was skipped and why.

    "extractable" is the protocol's test for keeping a repository: at least one
    statically extractable tool.
    """
    root = Path(root)
    tools, skipped = [], {"too_large": 0, "unreadable": 0, "unparsable": 0}
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            path = Path(folder) / name
            if not name.endswith(TS_SUFFIXES + PY_SUFFIXES) or name.endswith(".d.ts"):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    skipped["too_large"] += 1
                    continue
                src = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                skipped["unreadable"] += 1
                continue
            if name.endswith(PY_SUFFIXES):
                found = extract_python(src)
                if found is None:
                    skipped["unparsable"] += 1
                    continue
            else:
                found = extract_typescript(src)
            rel = path.relative_to(root).as_posix()
            tools.extend({**t, "file": rel} for t in found)
    static = [t for t in tools if t["kind"] == "static"]
    return {"tools": tools, "static": len(static), "dynamic": len(tools) - len(static), "skipped": skipped,
            "extractable": bool(static),
            "reason": None if static else ("only dynamic definitions" if tools else "no tool definition found")}
