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
