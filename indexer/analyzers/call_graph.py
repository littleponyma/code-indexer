"""Call graph analysis: hot functions, entry chains, leaf functions, cycles."""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from ..models import CallRelation, Symbol


def analyze_call_graph(
    symbols: list[Symbol],
    calls: list[CallRelation],
) -> dict:
    caller_map: dict[str, list[str]] = defaultdict(list)
    callee_map: dict[str, list[str]] = defaultdict(list)

    for call in calls:
        caller_map[call.callee_name].append(call.caller_name)
        callee_map[call.caller_name].append(call.callee_name)

    # Hot functions (most callers)
    hot_functions = sorted(
        [(name, len(callers)) for name, callers in caller_map.items()],
        key=lambda x: x[1],
        reverse=True,
    )[:20]

    # Leaf functions (no callees)
    all_callers = set(c.caller_name for c in calls)
    all_callees = set(c.callee_name for c in calls)
    leaf_funcs = all_callers - all_callees

    # Entry points
    entry_points = [
        s.name for s in symbols if s.is_entry_point
    ]

    # Entry chains: BFS from each entry point
    entry_chains = []
    for ep in entry_points:
        chain = _trace_chain(ep, callee_map, max_depth=10)
        if chain:
            entry_chains.append({"entry": ep, "chain": chain})

    # Cycle detection
    cycles = _detect_cycles(callee_map)

    return {
        "hot_functions": [{"name": name, "callers": count} for name, count in hot_functions],
        "leaf_functions": [{"name": name} for name in sorted(leaf_funcs)[:50]],
        "entry_points": entry_points,
        "entry_chains": entry_chains,
        "cycles": cycles[:10],
    }


def _trace_chain(entry: str, callee_map: dict[str, list[str]], max_depth: int = 10) -> list[str]:
    visited = set()
    chain = [entry]
    current = entry

    while len(chain) < max_depth:
        callees = callee_map.get(current, [])
        if not callees:
            break
        # Pick the callee that itself has the most callees (main path)
        next_func = max(callees, key=lambda c: len(callee_map.get(c, [])))
        if next_func in visited:
            break
        visited.add(next_func)
        chain.append(next_func)
        current = next_func

    return chain


def _detect_cycles(callee_map: dict[str, list[str]], max_cycles: int = 10) -> list[list[str]]:
    cycles = []
    visited_global = set()

    def dfs(node: str, path: list[str], visited: set[str]):
        if len(cycles) >= max_cycles:
            return
        if node in visited:
            cycle_start = path.index(node)
            cycle = path[cycle_start:] + [node]
            cycles.append(cycle)
            return

        visited.add(node)
        path.append(node)

        for callee in callee_map.get(node, []):
            dfs(callee, path, visited)

        path.pop()
        visited.discard(node)

    for start in list(callee_map.keys())[:50]:
        if start not in visited_global:
            dfs(start, [], set())
            visited_global.add(start)

    return cycles
