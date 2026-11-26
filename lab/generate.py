#!/usr/bin/env python3
"""Gerador do laboratório: produz pcap, labels.csv e metadado de um cenário.

Uso:
    python lab/generate.py --cenario <nome> --semente 42
    python lab/generate.py --scenario <nome> --seed 42          # mesmos argumentos em inglês

O plano (instantes das conexões benignas e todos os pacotes de ataque) é calculado aqui,
de forma determinística a partir da semente, e gravado em ``<nome>.plano.json``. Os
containers apenas executam o plano. Assim a mesma semente gera o mesmo tráfego; o pcap só
difere nos detalhes de temporização do kernel.

Segurança (regra 4 do guia): todo tráfego roda numa rede Docker ``--internal`` criada para
a geração e removida ao final. Os containers não têm rota para fora do host; o SYN Flood
usa origens forjadas numa faixa sem hosts (10.99.0.0/16 por padrão).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from tcpmon.config import carregar_yaml, tau_hs_de_synack_retries  # noqa: E402
from tcpmon.io.labels import Episodio, write_labels  # noqa: E402
from tcpmon.io.pcap_reader import ReadCounters, read_packets, sha256_arquivo  # noqa: E402

DIR_CENARIOS = Path(__file__).resolve().parent / "scenarios"
DIR_LAB = Path(__file__).resolve().parent

SYN, ACK, FIN, PSH, URG = 0x02, 0x10, 0x01, 0x08, 0x20
FLAGS_TIPO = {
    "ack_sem_syn": ACK,
    "xmas": FIN | PSH | URG,
    "null": 0,
    "handshake_incompleto": SYN,
    "synflood": SYN,
    "varredura_horizontal": SYN,
}
SYSCTLS_SERVIDOR = ("net.ipv4.tcp_synack_retries", "net.ipv4.tcp_syncookies", "net.ipv4.tcp_max_syn_backlog")


# --------------------------------------------------------------------------------------
# Cenários e plano
# --------------------------------------------------------------------------------------


def caminho_cenario(nome: str) -> Path:
    p = Path(nome)
    if p.suffix in (".yaml", ".yml") and p.is_file():
        return p
    for cand in (DIR_CENARIOS / f"{nome}.yaml", DIR_CENARIOS / "fixtures" / f"{nome}.yaml"):
        if cand.is_file():
            return cand
    raise SystemExit(f"cenário não encontrado: {nome} (procurado em {DIR_CENARIOS})")


def carregar_cenario(nome: str) -> dict:
    cen = carregar_yaml(caminho_cenario(nome))
    if "inclui" in cen:
        blocos = []
        for sub in cen["inclui"]:
            blocos.extend(carregar_yaml(caminho_cenario(sub)).get("blocos", []))
        cen["blocos"] = blocos
    cen.setdefault("blocos", [])
    if not cen["blocos"] and "duracao_benigna_s" not in cen:
        raise SystemExit(f"cenário {nome}: sem blocos de ataque e sem duracao_benigna_s")
    return cen


def _r(x: float) -> float:
    return round(float(x), 6)


def _poisson(rng: np.random.Generator, taxa: float, inicio: float, fim: float) -> list[float]:
    """Instantes de um processo de Poisson de taxa ``taxa`` em [inicio, fim)."""
    out = []
    if taxa <= 0:
        return out
    t = inicio
    while True:
        t += rng.exponential(1.0 / taxa)
        if t >= fim:
            return out
        out.append(t)


def _faixa_portas(cen: dict, tipo: str, n: int) -> range:
    lo, hi = cen["portas_origem"][tipo]
    if n > hi - lo + 1:
        raise SystemExit(
            f"{tipo}: {n} pacotes exigem {n} portas de origem distintas, mas a faixa {lo}-{hi} tem {hi - lo + 1}"
        )
    return range(lo, lo + n)


class _Contador:
    def __init__(self) -> None:
        self.n = 0

    def proximo(self) -> str:
        self.n += 1
        return f"e{self.n:03d}"


def _bloco_continuo(tipo, bloco, cen, t, cont, idx_bloco):
    srv, atk = cen["servidor"], cen["atacante"]
    taxa, dur = float(bloco["taxa_pps"]), float(bloco["duracao_s"])
    n = int(round(dur * taxa))
    portas = _faixa_portas(cen, tipo, n)
    pacotes = []
    for j in range(n):
        if tipo == "varredura_horizontal":
            base = ipaddress.ip_address(cen["alvos"]["primeiro_ip"])
            dst, dport = str(base + (j % int(cen["alvos"]["n"]))), int(bloco["porta_destino"])
        elif "portas_destino" in bloco:
            lo, hi = bloco["portas_destino"]
            dst, dport = srv["ip"], lo + (j % (hi - lo + 1))
        else:
            dst, dport = srv["ip"], int(bloco["porta_destino"])
        pacotes.append([_r(t + j / taxa), atk["ip"], portas[j], dst, dport, FLAGS_TIPO[tipo]])
    ep = {
        "episodio": cont.proximo(),
        "classe": bloco["classe"],
        "inicio_s": _r(t),
        "fim_s": _r(t + dur),
        "pontual": False,
        "chave_tipo": "origem",
        "chave_valor": atk["ip"],
        "parametros": {"tipo": tipo, "taxa_pps": taxa, "duracao_s": dur, "bloco": idx_bloco},
        "pacotes": pacotes,
    }
    return [ep], t + dur + float(cen["intervalo_s"])


def _bloco_handshake(bloco, cen, t, cont, idx_bloco):
    srv, atk = cen["servidor"], cen["atacante"]
    n, esp = int(bloco["n_syn"]), float(bloco["espacamento_s"])
    portas = _faixa_portas(cen, "handshake_incompleto", n)
    eps = []
    for j in range(n):
        off = _r(t + j * esp)
        eps.append(
            {
                "episodio": cont.proximo(),
                "classe": bloco["classe"],
                "inicio_s": off,
                "fim_s": off,
                "pontual": True,
                "chave_tipo": "servidor",
                "chave_valor": srv["ip"],
                "parametros": {"tipo": "handshake_incompleto", "espacamento_s": esp, "indice": j, "bloco": idx_bloco},
                "pacotes": [[off, atk["ip"], portas[j], srv["ip"], int(bloco["porta_destino"]), SYN]],
            }
        )
    return eps, t + (n - 1) * esp + float(cen["intervalo_s"])


def _bloco_synflood(bloco, cen, t, cont, idx_bloco, rng):
    srv = cen["servidor"]
    rede = ipaddress.ip_network(cen["faixa_forjada"])
    n_hosts = rede.num_addresses
    dur = float(bloco["duracao_s"])
    eps = []
    for taxa in bloco["taxas_s"]:
        taxa = float(taxa)
        instantes = _poisson(rng, taxa, t, t + dur)
        hosts = rng.integers(1, n_hosts - 1, size=len(instantes))
        sports = rng.integers(1024, 65536, size=len(instantes))
        pacotes = [
            [_r(ti), str(rede.network_address + int(h)), int(sp), srv["ip"], int(bloco["porta_destino"]), SYN]
            for ti, h, sp in zip(instantes, hosts, sports)
        ]
        eps.append(
            {
                "episodio": cont.proximo(),
                "classe": bloco["classe"],
                "inicio_s": _r(t),
                "fim_s": _r(t + dur),
                "pontual": False,
                "chave_tipo": "servidor",
                "chave_valor": srv["ip"],
                "parametros": {
                    "tipo": "synflood",
                    "lambda_A": taxa,
                    "duracao_s": dur,
                    "faixa_forjada": cen["faixa_forjada"],
                    "bloco": idx_bloco,
                },
                "pacotes": pacotes,
            }
        )
        t += dur + float(cen["intervalo_s"])
    return eps, t


def construir_plano(cen: dict, semente: int) -> dict:
    """Plano determinístico: mesma semente e mesmo cenário produzem o mesmo plano."""
    blocos = cen["blocos"]
    filhos = np.random.SeedSequence(semente).spawn(1 + len(blocos))
    cont = _Contador()
    episodios = []
    t = float(cen["aquecimento_s"]) if blocos else 0.0
    for i, bloco in enumerate(blocos):
        tipo = bloco["tipo"]
        rng = np.random.default_rng(filhos[1 + i])
        if tipo in ("ack_sem_syn", "xmas", "null", "varredura_horizontal"):
            eps, t = _bloco_continuo(tipo, bloco, cen, t, cont, i)
        elif tipo == "handshake_incompleto":
            eps, t = _bloco_handshake(bloco, cen, t, cont, i)
        elif tipo == "synflood":
            eps, t = _bloco_synflood(bloco, cen, t, cont, i, rng)
        else:
            raise SystemExit(f"tipo de bloco desconhecido: {tipo}")
        for e in eps:
            e["parametros"]["semente"] = semente
        episodios.extend(eps)
    duracao = t if blocos else float(cen["duracao_benigna_s"])

    rng_b = np.random.default_rng(filhos[0])
    instantes = [_r(x) for x in _poisson(rng_b, float(cen["benigno"]["taxa_conexoes_s"]), 0.0, duracao)]
    return {
        "cenario": cen["nome"],
        "semente": semente,
        "duracao_s": _r(duracao),
        "benigno": {
            "servidor": cen["servidor"]["ip"],
            "porta": int(cen["servidor"]["porta"]),
            "timeout_s": float(cen["benigno"]["timeout_s"]),
            "taxa_conexoes_s": float(cen["benigno"]["taxa_conexoes_s"]),
            "instantes_s": instantes,
        },
        "episodios": episodios,
    }


def hash_plano(plano: dict) -> str:
    canon = json.dumps(plano, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


# --------------------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------------------


def sh(cmd: list[str], check: bool = True, capture: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    if check and r.returncode != 0:
        raise RuntimeError(f"comando falhou ({r.returncode}): {' '.join(cmd)}\n{r.stderr}")
    return (r.stdout or "").strip()


def imagem_lab(nome: str) -> str:
    """Constrói a imagem (cache do Docker) e devolve seu ID."""
    sh(["docker", "build", "-q", "-t", f"{nome}:lab", str(DIR_LAB)])
    return sh(["docker", "image", "inspect", "-f", "{{.Id}}", f"{nome}:lab"])


class Laboratorio:
    def __init__(self, cen: dict, tag: str, workdir: Path, imagem: str) -> None:
        self.cen, self.tag, self.workdir, self.imagem = cen, tag, workdir, imagem
        self.rede = f"tcpmon-{tag}"
        self.ponte = f"tml{os.getpid() % 1000000}"
        self.containers: list[str] = []

    def nome(self, papel: str) -> str:
        return f"tcpmon-{self.tag}-{papel}"

    def _run(self, papel: str, args: list[str], ip: str | None = None, rede: bool = True) -> str:
        nome = self.nome(papel)
        cmd = ["docker", "run", "-d", "--init", "--name", nome, "-v", f"{self.workdir}:/data:z"]
        if rede:
            cmd += ["--network", self.rede]
            if ip:
                cmd += ["--ip", ip]
        cmd += args
        sh(cmd)
        self.containers.append(nome)
        return nome

    def exec(self, papel: str, args: list[str], detach: bool = False) -> str:
        cmd = ["docker", "exec"] + (["-d"] if detach else []) + [self.nome(papel)] + args
        return sh(cmd)

    def subir(self, precisa_alvos: bool) -> None:
        c = self.cen
        sh(
            [
                "docker", "network", "create", "--internal",
                "--subnet", c["rede"]["sub_rede"],
                "-o", f"com.docker.network.bridge.name={self.ponte}",
                self.rede,
            ]
        )
        img = self.imagem
        srv = c["servidor"]
        self._run(
            "servidor",
            ["--cap-add", "NET_ADMIN", img, "python", "/lab/server.py",
             "--porta", str(srv["porta"]), "--backlog", str(srv["backlog"])],
            ip=srv["ip"],
        )
        # SYN-ACKs para a faixa forjada saem pela rede até o atacante, que os descarta em
        # silêncio (ip_forward = 0): aparecem na captura e ninguém responde com RST.
        self.exec("servidor", ["ip", "route", "add", c["faixa_forjada"], "via", c["atacante"]["ip"]])

        self._run("cliente", ["--cap-add", "NET_ADMIN", img, "sleep", "infinity"], ip=c["cliente"]["ip"])
        nt = c["netem"]
        self.exec(
            "cliente",
            ["tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "netem",
             "delay", f"{nt['delay_ms']}ms", f"{nt['jitter_ms']}ms", "distribution", nt["distribuicao"]],
        )
        # Fila FIFO filha: o atraso varia, mas a ordem dos pacotes é preservada (DECISIONS.md).
        self.exec(
            "cliente",
            ["tc", "qdisc", "add", "dev", "eth0", "parent", "1:1", "handle", "10:", "pfifo",
             "limit", str(nt["limite_fila"])],
        )

        self._run(
            "atacante",
            ["--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--sysctl", "net.ipv4.ip_forward=0",
             img, "sleep", "infinity"],
            ip=c["atacante"]["ip"],
        )
        lo, hi = c["portas_origem"]["handshake_incompleto"]
        self.exec(
            "atacante",
            ["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST",
             "--sport", f"{lo}:{hi}", "-j", "DROP"],
        )

        if precisa_alvos:
            base = ipaddress.ip_address(c["alvos"]["primeiro_ip"])
            for i in range(int(c["alvos"]["n"])):
                self._run(
                    f"alvo{i:02d}",
                    [img, "python", "/lab/listener.py", "--porta", str(c["alvos"]["porta"]),
                     "--backlog", str(c["alvos"]["backlog"])],
                    ip=str(base + i),
                )

    def sysctls_servidor(self) -> dict[str, int]:
        out = {}
        for nome in SYSCTLS_SERVIDOR:
            out[nome] = int(self.exec("servidor", ["sysctl", "-n", nome]))
        return out

    def iniciar_captura(self) -> None:
        self._run(
            "captura",
            ["--network", "host", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", self.imagem,
             "tcpdump", "-i", self.ponte, "-s", str(self.cen["captura"]["snaplen"]), "-U", "-n",
             "-w", "/data/captura.pcap"],
            rede=False,
        )
        arq = self.workdir / "captura.pcap"
        limite = time.time() + 20
        while time.time() < limite:
            if arq.exists() and arq.stat().st_size >= 24:
                return
            time.sleep(0.2)
        raise RuntimeError("tcpdump não iniciou a captura:\n" + sh(["docker", "logs", self.nome("captura")], check=False))

    def parar_captura(self) -> dict:
        sh(["docker", "stop", "-t", "15", self.nome("captura")], check=False)
        r = subprocess.run(["docker", "logs", self.nome("captura")], capture_output=True, text=True)
        logs = (r.stdout or "") + (r.stderr or "")
        stats = {}
        for chave, padrao in (
            ("capturados", r"(\d+) packets? captured"),
            ("recebidos_pelo_filtro", r"(\d+) packets? received by filter"),
            ("descartados_pelo_kernel", r"(\d+) packets? dropped by kernel"),
        ):
            m = re.search(padrao, logs)
            stats[chave] = int(m.group(1)) if m else None
        return stats

    def corrigir_dono(self) -> None:
        sh(
            ["docker", "run", "--rm", "-v", f"{self.workdir}:/data:z", self.imagem,
             "chown", "-R", f"{os.getuid()}:{os.getgid()}", "/data"],
            check=False,
        )

    def derrubar(self) -> None:
        for nome in reversed(self.containers):
            sh(["docker", "rm", "-f", nome], check=False)
        sh(["docker", "network", "rm", self.rede], check=False)


# --------------------------------------------------------------------------------------
# Rótulos
# --------------------------------------------------------------------------------------


def construir_rotulos(plano: dict, inicio: float, pcap: Path, log_ataque: dict) -> tuple[list[Episodio], dict]:
    """Converte os episódios do plano em rótulos com tempo absoluto (relógio do host, o mesmo
    do pcap). Episódios contínuos usam o intervalo planejado; episódios pontuais usam o
    timestamp capturado do próprio pacote de ataque (o plano é o fallback)."""
    indice: dict[tuple, int] = {}
    for i, ep in enumerate(plano["episodios"]):
        for _, src, sport, dst, dport, flags in ep["pacotes"]:
            indice[(src, sport, dst, dport, flags)] = i
    n = len(plano["episodios"])
    capt = [0] * n
    prim: list[float | None] = [None] * n
    ult: list[float | None] = [None] * n
    cont = ReadCounters()
    for p in read_packets(pcap, cont):
        i = indice.get((p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.flags))
        if i is None:
            continue
        capt[i] += 1
        if prim[i] is None:
            prim[i] = p.ts
        ult[i] = p.ts
    enviados = {e["episodio"]: e for e in log_ataque.get("episodios", [])}

    episodios = []
    for i, ep in enumerate(plano["episodios"]):
        params = dict(ep["parametros"])
        env = enviados.get(ep["episodio"], {})
        params.update(
            {
                "n_planejados": len(ep["pacotes"]),
                "n_enviados": env.get("enviados"),
                "n_capturados": capt[i],
                "t_primeiro_capturado": prim[i],
                "t_ultimo_capturado": ult[i],
            }
        )
        if ep["pontual"] and prim[i] is not None:
            t_ini = t_fim = prim[i]
            params["origem_tempo"] = "pcap"
        else:
            t_ini, t_fim = inicio + ep["inicio_s"], inicio + ep["fim_s"]
            params["origem_tempo"] = "plano"
        episodios.append(
            Episodio(ep["episodio"], ep["classe"], t_ini, t_fim, ep["chave_tipo"], ep["chave_valor"], params)
        )
    return episodios, cont.as_dict()


# --------------------------------------------------------------------------------------
# Principal
# --------------------------------------------------------------------------------------


def _commit_git() -> str | None:
    try:
        return sh(["git", "-C", str(REPO), "rev-parse", "HEAD"])
    except RuntimeError:
        return None


def gerar(args: argparse.Namespace) -> int:
    cen = carregar_cenario(args.cenario)
    nome = args.nome or f"{cen['nome']}_s{args.semente}"
    saida = Path(args.saida_dir).resolve()
    saida.mkdir(parents=True, exist_ok=True)

    plano = construir_plano(cen, args.semente)
    h = hash_plano(plano)
    arq_plano = saida / f"{nome}.plano.json"
    arq_plano.write_text(json.dumps(plano, separators=(",", ":")))
    n_ataque = sum(len(e["pacotes"]) for e in plano["episodios"])
    print(
        f"[plano] {cen['nome']} semente={args.semente} duração={plano['duracao_s']:.0f}s "
        f"episódios={len(plano['episodios'])} pacotes_ataque={n_ataque} "
        f"conexões_benignas={len(plano['benigno']['instantes_s'])} sha256={h[:12]}",
        flush=True,
    )
    if args.apenas_plano:
        return 0

    tag = f"{re.sub(r'[^a-z0-9]', '', nome.lower())[:20]}-{os.getpid()}"
    workdir = saida / f".tmp-{tag}"
    workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy(arq_plano, workdir / "plano.json")
    imagem = imagem_lab(cen["imagem"])
    lab = Laboratorio(cen, tag, workdir, imagem)
    precisa_alvos = any(b["tipo"] == "varredura_horizontal" for b in cen["blocos"])
    t_inicio_geracao = time.time()
    try:
        lab.subir(precisa_alvos)
        sysctls = lab.sysctls_servidor()
        r = sysctls["net.ipv4.tcp_synack_retries"]
        tau = tau_hs_de_synack_retries(r, float(cen["rto_inicial_s"]))
        lab.iniciar_captura()
        inicio = time.time() + float(cen["espera_inicio_s"])
        lab.exec("cliente", ["python", "/lab/client.py", "--plano", "/data/plano.json",
                             "--inicio", repr(inicio), "--log", "/data/cliente_log.json"], detach=True)
        if plano["episodios"]:
            lab.exec("atacante", ["python", "/lab/attack.py", "--plano", "/data/plano.json",
                                  "--inicio", repr(inicio), "--log", "/data/ataque_log.json"], detach=True)
        fim = inicio + plano["duracao_s"]
        while (agora := time.time()) < fim:
            print(f"[lab] {agora - inicio:7.0f}s / {plano['duracao_s']:.0f}s", flush=True)
            time.sleep(min(60.0, max(0.5, fim - agora)))
        logs = [workdir / "cliente_log.json"] + ([workdir / "ataque_log.json"] if plano["episodios"] else [])
        limite = time.time() + float(cen["espera_logs_s"])
        while time.time() < limite and not all(p.exists() for p in logs):
            time.sleep(0.5)
        time.sleep(1.0)
        stats_captura = lab.parar_captura()
    finally:
        lab.corrigir_dono()
        if not args.manter:
            lab.derrubar()

    pcap = saida / f"{nome}.pcap"
    shutil.move(workdir / "captura.pcap", pcap)
    log_cliente = json.loads((workdir / "cliente_log.json").read_text()) if (workdir / "cliente_log.json").exists() else {}
    log_ataque = json.loads((workdir / "ataque_log.json").read_text()) if (workdir / "ataque_log.json").exists() else {}
    episodios, cont_leitura = construir_rotulos(plano, inicio, pcap, log_ataque)
    write_labels(saida / f"{nome}_labels.csv", episodios)

    conexoes = log_cliente.get("conexoes", [])
    erros: dict[str, int] = {}
    for c in conexoes:
        if c and c.get("erro"):
            erros[c["erro"]] = erros.get(c["erro"], 0) + 1
    meta = {
        "cenario": cen["nome"],
        "semente": args.semente,
        "plano_sha256": h,
        "pcap": pcap.name,
        "pcap_sha256": sha256_arquivo(pcap),
        "inicio_plano": inicio,
        "duracao_plano_s": plano["duracao_s"],
        "sysctls_servidor": sysctls,
        "tau_hs_s": tau,
        "tau_hs_origem": f"net.ipv4.tcp_synack_retries={r} lido do container servidor; RTO inicial {cen['rto_inicial_s']} s",
        "rto_inicial_s": float(cen["rto_inicial_s"]),
        "cenario_config": {k: v for k, v in cen.items() if k != "blocos"} | {"blocos": cen["blocos"]},
        "imagem_docker": imagem,
        "captura": stats_captura,
        "leitura": cont_leitura,
        "benigno": {
            "conexoes_planejadas": len(plano["benigno"]["instantes_s"]),
            "conexoes_registradas": sum(1 for c in conexoes if c),
            "erros": erros,
        },
        "ataque": log_ataque.get("episodios", []),
        "ambiente": {
            "host_kernel": platform.release(),
            "docker": sh(["docker", "version", "-f", "{{.Server.Version}}"], check=False),
            "python_gerador": platform.python_version(),
            "commit_git": _commit_git(),
        },
        "duracao_geracao_s": time.time() - t_inicio_geracao,
    }
    (saida / f"{nome}.meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    if not args.manter:
        shutil.rmtree(workdir, ignore_errors=True)
    print(
        f"[ok] {pcap} ({pcap.stat().st_size / 1e6:.1f} MB, {cont_leitura['pacotes_lidos']} pacotes, "
        f"descartados pelo kernel na captura: {stats_captura.get('descartados_pelo_kernel')}) "
        f"tau_hs={tau:g}s rótulos={len(episodios)}",
        flush=True,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Gera pcap, labels.csv e metadado de um cenário do laboratório.")
    ap.add_argument("--cenario", "--scenario", dest="cenario", required=True, help="nome do cenário ou caminho do YAML")
    ap.add_argument("--semente", "--seed", dest="semente", type=int, required=True)
    ap.add_argument("--saida-dir", default=str(REPO / "data" / "lab"), help="pasta de saída (padrão: data/lab)")
    ap.add_argument("--nome", default=None, help="prefixo dos arquivos (padrão: <cenario>_s<semente>)")
    ap.add_argument("--apenas-plano", action="store_true", help="só calcula e grava o plano, sem Docker")
    ap.add_argument("--manter", action="store_true", help="não remove containers e rede ao final (depuração)")
    return gerar(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
