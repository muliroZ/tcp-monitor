"""Inclusão de alertas entre configurações cumulativas.

Para o mesmo pcap, todo alerta de C1 deve aparecer igual em C2, e todo alerta de C2 deve
aparecer igual em C3. Esta verificação garante que a base é compartilhada; violações são
reportadas como estão (nunca filtradas).
"""

from __future__ import annotations

from collections import Counter

from tcpmon.alerts import Alerta


def alertas_ausentes(menor: list[Alerta], maior: list[Alerta]) -> list[Alerta]:
    """Alertas de ``menor`` sem correspondente idêntico em ``maior`` (multiconjunto)."""
    disponiveis = Counter(a.identidade() for a in maior)
    faltando = []
    for a in menor:
        ident = a.identidade()
        if disponiveis[ident] > 0:
            disponiveis[ident] -= 1
        else:
            faltando.append(a)
    return faltando
