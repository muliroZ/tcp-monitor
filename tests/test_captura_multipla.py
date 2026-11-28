"""D73: captura em vários arquivos (pasta) e recorte no tempo."""

import json

import pytest
from conftest import REPO
from pcaputil import CLI, FLAGS, SRV, P, handshake_completo, write_pcap, write_pcapng

from tcpmon.cli import main
from tcpmon.config import ConfigError, from_dict, load_config
from tcpmon.io.pcap_reader import (
    PcapError,
    ReadCounters,
    arquivos_da_captura,
    read_captura,
    sha256_arquivo,
    sha256_captura,
)


def pasta_com_partes(tmp_path):
    """Três partes numeradas como no CIC-DDoS2019 (_0, _01, _02 ... _010)."""
    d = tmp_path / "captura"
    d.mkdir()
    write_pcap(d / "x_0", [P(0.0, CLI, SRV, FLAGS["SYN"])])
    write_pcapng(d / "x_01", [P(1.0, SRV, CLI, FLAGS["SYNACK"]), P(2.0, CLI, SRV, FLAGS["ACK"])])
    write_pcap(d / "x_010", [P(1.5, CLI, SRV, FLAGS["ACK"]), P(10.0, CLI, SRV, FLAGS["FIN"])])  # 1.5 < 2.0
    write_pcap(d / "x_02", [P(3.0, CLI, SRV, FLAGS["PSHACK"])])
    (d / ".oculto").write_text("ignorar")
    return d


def test_ordem_natural_dos_arquivos(tmp_path):
    d = pasta_com_partes(tmp_path)
    assert [a.name for a in arquivos_da_captura(d)] == ["x_0", "x_01", "x_02", "x_010"]
    with pytest.raises(PcapError, match="não encontrado"):
        arquivos_da_captura(tmp_path / "nada")
    (tmp_path / "vazia").mkdir()
    with pytest.raises(PcapError, match="vazia"):
        arquivos_da_captura(tmp_path / "vazia")


def test_leitura_em_sequencia_conta_inversoes_entre_arquivos(tmp_path):
    d = pasta_com_partes(tmp_path)
    c = ReadCounters()
    ts = [p.ts for p in read_captura(d, c)]
    assert ts == [0.0, 1.0, 2.0, 3.0, 1.5, 10.0]
    assert c.arquivos == 4 and c.lidos == 6
    assert c.inversoes_ordem == 1  # 3.0 (fim de x_02) -> 1.5 (início de x_010)
    assert c.primeiro_ts == 0.0 and c.max_ts == 10.0


def test_recorte_no_tempo(tmp_path):
    d = pasta_com_partes(tmp_path)
    c = ReadCounters()
    ts = [p.ts for p in read_captura(d, c, inicio=1.0, fim=3.0)]
    # [1.0, 3.0): pula 0.0; para no primeiro quadro >= 3.0 e não lê os arquivos seguintes.
    assert ts == [1.0, 2.0]
    assert c.antes_do_inicio == 1 and c.parou_no_fim and c.arquivos == 3
    assert c.primeiro_ts == 1.0 and c.max_ts == 2.0


def test_hash_da_captura(tmp_path):
    d = pasta_com_partes(tmp_path)
    h = sha256_captura(d)
    assert h["arquivos"] == 4 and set(h["sha256_por_arquivo"]) == {"x_0", "x_01", "x_02", "x_010"}
    arq = d / "x_0"
    assert sha256_captura(arq) == {"sha256": sha256_arquivo(arq), "arquivos": 1}


def test_instantes_na_configuracao():
    raw = load_config(REPO / "configs" / "default.yaml").raw
    raw["entrada"]["inicio"] = "2018-11-03T09:18:00-03:00"
    raw["entrada"]["fim"] = 1541248920.0  # 2018-11-03T09:42:00-03:00
    cfg = from_dict(raw)
    assert cfg.entrada.inicio == 1541247480.0 and cfg.entrada.fim == 1541248920.0
    for ruim, msg in (("2018-11-03T09:18:00", "fuso explícito"), ("ontem", "ISO 8601")):
        raw["entrada"]["inicio"] = ruim
        with pytest.raises(ConfigError, match=msg):
            from_dict(raw)
    raw["entrada"]["inicio"] = 1541248920.0
    with pytest.raises(ConfigError, match="posterior"):
        from_dict(raw)


def test_yaml_com_datetime_vira_texto(tmp_path):
    exp = tmp_path / "exp.yaml"
    exp.write_text(f"base: {REPO / 'configs' / 'default.yaml'}\nentrada:\n  inicio: 2018-11-03T09:18:00-03:00\n")
    cfg = load_config(exp)
    assert cfg.entrada.inicio == 1541247480.0
    assert cfg.raw["entrada"]["inicio"] == "2018-11-03T09:18:00-03:00"
    json.dumps(cfg.raw)  # vai para run.json


def test_run_sobre_pasta_com_recorte(tmp_path):
    d = tmp_path / "partes"
    d.mkdir()
    write_pcap(d / "a_0", handshake_completo(0.0))
    write_pcap(d / "a_01", handshake_completo(50.0, cli=("10.0.0.5", 41000)))
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"base: {REPO / 'configs' / 'default.yaml'}\ncamadas: [1, 2]\nsaida: {tmp_path / 'res'}\n")
    assert main(["run", "--config", str(cfg), "--pcap", str(d), "--fim", "40"]) == 0
    (pasta,) = (tmp_path / "res").iterdir()
    run = json.loads((pasta / "run.json").read_text())
    assert run["pcap"]["arquivos"] == 2 and run["pcap"]["fim"] == 40.0 and run["pcap"]["inicio"] is None
    assert run["config"]["entrada"]["fim"] == 40.0
    cont = json.loads((pasta / "counters.json").read_text())["leitura"]
    assert cont["parou_no_fim"] and cont["arquivos"] == 2 and cont["max_ts"] < 40.0
    # Texto vazio remove o limite da configuração (usado na calibração, D73).
    cfg2 = tmp_path / "cfg2.yaml"
    cfg2.write_text(cfg.read_text().replace(f"saida: {tmp_path / 'res'}", f"saida: {tmp_path / 'res2'}") + "entrada:\n  fim: 40.0\n")
    assert main(["run", "--config", str(cfg2), "--pcap", str(d), "--fim", ""]) == 0
    (pasta2,) = (tmp_path / "res2").iterdir()
    assert json.loads((pasta2 / "run.json").read_text())["pcap"]["fim"] is None

