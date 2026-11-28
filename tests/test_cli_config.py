import subprocess
import sys

import pytest
from conftest import REPO
from pcaputil import handshake_completo, write_pcap

from tcpmon.cli import main
from tcpmon.config import ConfigError, from_dict, load_config, tau_hs_de_synack_retries


def test_help_funciona(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "symbols" in capsys.readouterr().out


def test_executavel_tcpmon_help():
    exe = REPO / ".venv" / "bin" / "tcpmon"
    cmd = [str(exe), "--help"] if exe.exists() else [sys.executable, "-m", "tcpmon.cli", "--help"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "tcpmon" in r.stdout


def test_symbols_imprime_sequencia(tmp_path, capsys):
    arq = write_pcap(tmp_path / "hs.pcap", handshake_completo())
    assert main(["symbols", "--pcap", str(arq)]) == 0
    out = capsys.readouterr().out
    linhas = [l.split()[-1] for l in out.splitlines() if l.startswith("  ")]
    assert linhas == ["C.SYN", "S.SYNACK", "C.ACK", "C.ACK", "S.ACK", "S.FIN", "C.FIN", "S.ACK"]


def test_config_padrao_carrega():
    cfg = load_config(REPO / "configs" / "default.yaml")
    assert cfg.camadas == (1, 2, 3)
    assert cfg.tau_hs_s == 63.0
    assert cfg.semente == 42
    assert len(cfg.hash_curto()) == 8


def test_config_heranca(tmp_path):
    exp = tmp_path / "exp.yaml"
    exp.write_text(f"base: {REPO / 'configs' / 'default.yaml'}\ncamadas: [1]\njanela_s: 5.0\n")
    cfg = load_config(exp)
    assert cfg.camadas == (1,) and cfg.janela_s == 5.0 and cfg.alfa == 0.01


def test_config_sem_chaves_obrigatorias():
    with pytest.raises(ConfigError, match="obrigatórias"):
        from_dict({"semente": 1})


def test_config_camadas_nao_cumulativas():
    raw = load_config(REPO / "configs" / "default.yaml").raw
    raw["camadas"] = [1, 3]
    with pytest.raises(ConfigError, match="cumulativa"):
        from_dict(raw)


def test_hash_muda_com_config():
    cfg = load_config(REPO / "configs" / "default.yaml")
    assert cfg.hash_curto() != cfg.com(janela_s=5.0).hash_curto()


def test_tau_padrao_linux():
    assert tau_hs_de_synack_retries(5, 1.0) == 63.0
    assert tau_hs_de_synack_retries(0, 1.0) == 1.0
    assert tau_hs_de_synack_retries(2, 1.0) == 7.0


def test_config_exige_avaliacao():
    raw = load_config(REPO / "configs" / "default.yaml").raw
    del raw["avaliacao"]
    with pytest.raises(ConfigError, match="avaliacao"):
        from_dict(raw)
    raw["avaliacao"] = {"sensibilidade_tolerancia_s": [60]}
    with pytest.raises(ConfigError, match="tolerancia_rotulo_s"):
        from_dict(raw)
    raw["avaliacao"] = {"tolerancia_rotulo_s": -1}
    with pytest.raises(ConfigError, match="tolerancia_rotulo_s"):
        from_dict(raw)


def test_config_avaliacao_padrao():
    cfg = load_config(REPO / "configs" / "default.yaml")
    assert cfg.avaliacao.tolerancia_rotulo_s == 0.0 and cfg.avaliacao.sensibilidade_tolerancia_s == ()
    assert cfg.tau_hs_origem is None
    assert cfg.avaliacao.classes_fora_da_conta == ()
    raw = cfg.raw
    raw["avaliacao"]["classes_fora_da_conta"] = ["a", 3]
    with pytest.raises(ConfigError, match="classes_fora_da_conta"):
        from_dict(raw)


def test_tau_origem_declarada(tmp_path):
    """D39: sem metadado do laboratório, run.json grava a origem declarada na configuração."""
    from tcpmon.pipeline import resolver_tau

    pcap = tmp_path / "dia.pcap"  # sem .meta.json ao lado
    cfg = load_config(REPO / "configs" / "default.yaml")
    assert resolver_tau(cfg, pcap) == (63.0, "configuração (tau_hs_s)", None)
    cfg = cfg.com(tau_hs_origem="documentacao_dataset")
    assert resolver_tau(cfg, pcap) == (63.0, "documentacao_dataset", None)
    with pytest.raises(ConfigError, match="tau_hs_origem"):
        cfg.com(tau_hs_origem=63)

