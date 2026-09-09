"""看板统计（与 store.js stats 派生口径一致，供导出/看板复用）。"""

from __future__ import annotations


def project_stats(hosts: list, shells: list, links: list, creds: list, flags: list, segments: list) -> dict:
    owned = [h for h in hosts if h.owned and not h.is_local]
    max_layer = 0
    for h in hosts:
        try:
            max_layer = max(max_layer, int(str(h.layer).replace("L", "")))
        except ValueError:
            continue
    return {
        "hosts": len([h for h in hosts if not h.is_local]),
        "ownedHosts": len(owned),
        "links": len(links),
        "aliveLinks": len([l for l in links if l.status == "alive"]),
        "shells": len(shells),
        "aliveShells": len([s for s in shells if s.alive]),
        "creds": len(creds),
        "flags": len(flags),
        "segments": len(segments),
        "maxLayer": max_layer,
    }
