"""Ajudantes para rodar o motor sobre pacotes sintéticos nos testes."""

from tcpmon.engine import Engine, ParametrosEngine, SaidaMemoria


def params(camadas=(1,), **kw):
    base = dict(
        janela_s=1.0,
        tau_hs_s=63.0,
        carencia_s=0.0,
        msl_s=60.0,
        ocioso_estabelecido_s=3600.0,
        camadas=tuple(camadas),
    )
    base.update(kw)
    return ParametrosEngine(**base)


def rodar(pacotes, camadas=(1,), t0=None, t_ultimo=None, **kw):
    e = Engine(params(camadas, **kw), SaidaMemoria())
    e.rodar(sorted(pacotes, key=lambda p: p.ts), t0=t0, t_ultimo=t_ultimo)
    return e


def motivos(engine):
    return [a.motivo for a in engine.alertas]


def fluxos_por_id(engine):
    return {f.id: f for f in engine.saida.fluxos}
