"""
Descrição: Cliente UDP de Upload de Arquivos (Questão 2 da Atividade 2 - UDP).
           Envia arquivos locais em blocos de 1024 bytes utilizando o protocolo binário:
             - INICIO (seq 0): Envia nome e tamanho do arquivo em bytes (long).
             - DADOS (seq 1..N): Transmite cada bloco de 1024 bytes com cálculo de SHA-1.
             - FIM (seq N+1): Transmite o checksum SHA-1 e aguarda a confirmação (RESULTADO).
           Utiliza algoritmo Stop-and-Wait com retransmissão por timeout para garantir
           entrega confiável sobre o protocolo UDP não confiável.
           Exibe barra de progresso visual no terminal durante a transferência.
Autores: Daniel Suzuki Naves e Pedro Borges De Araujo
Data de criação: 07/10/2026
Última atualização: 09/10/2026
"""

import os
import sys
import time
import socket
import struct
import random
import hashlib
from typing import Optional, Callable

# Constantes do Protocolo
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 6000

TIPO_INICIO = 1
TIPO_DADOS = 2
TIPO_FIM = 3
TIPO_ACK = 4
TIPO_RESULTADO = 5

STATUS_OK = 0
STATUS_CHECKSUM_DIVERGENTE = 1
STATUS_ERRO = 2

HEADER_FORMAT = ">BII"  # tipo (1B), idTransferencia (4B), sequencia (4B)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

TIMEOUT_PADRAO_SEG = 0.3
MAX_TENTATIVAS = 40


class ResultadoUpload:
    """Resultado retornado pelo servidor após a conclusão da transferência."""

    def __init__(self, status: int, mensagem: str):
        self.status = status
        self.mensagem = mensagem

    def is_sucesso(self) -> bool:
        return self.status == STATUS_OK


class ClienteUploadUDP:
    """Cliente de Upload de arquivos via UDP com confiabilidade Stop-and-Wait."""

    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT, timeout_seg: float = TIMEOUT_PADRAO_SEG):
        """Inicializa os parâmetros do cliente.

        Args:
            host (str): Endereço IP do servidor UDP.
            port (int): Porta UDP do servidor.
            timeout_seg (float): Tempo limite em segundos de espera por ACK antes de retransmitir.
        """
        self.host = host
        self.port = port
        self.timeout_seg = timeout_seg

    def _enviar_e_aguardar(self, sock: socket.socket, id_trans: int, seq_esperada: int, tipo_envio: int, carga_envio: bytes, espera_resultado: bool) -> tuple[int, int, int, bytes]:
        """Envia um pacote e aguarda a confirmação (ACK ou RESULTADO) retransmitindo se houver timeout.

        Args:
            sock (socket.socket): Socket UDP ativo.
            id_trans (int): ID da transferência.
            seq_esperada (int): Sequência esperada no ACK/RESULTADO.
            tipo_envio (int): Tipo do pacote enviado (INICIO, DADOS ou FIM).
            carga_envio (bytes): Carga do pacote enviado.
            espera_resultado (bool): Se True, aguarda TIPO_RESULTADO; se False, aguarda TIPO_ACK.

        Returns:
            tuple[int, int, int, bytes]: (tipo_resp, id_resp, seq_resp, carga_resp)

        Raises:
            TimeoutError: Se exceder o número máximo de retransmissões sem resposta.
            OSError: Se o servidor abortar a transferência.
        """
        header = struct.pack(HEADER_FORMAT, tipo_envio, id_trans, seq_esperada)
        pacote = header + carga_envio

        for tentativa in range(1, MAX_TENTATIVAS + 1):
            sock.sendto(pacote, (self.host, self.port))
            sock.settimeout(self.timeout_seg)

            start_time = time.time()
            while True:
                tempo_restante = self.timeout_seg - (time.time() - start_time)
                if tempo_restante <= 0:
                    break  # Timeout: retransmite

                try:
                    sock.settimeout(tempo_restante)
                    dados_resp, _ = sock.recvfrom(2048)
                    if len(dados_resp) < HEADER_SIZE:
                        continue

                    t_resp, id_resp, seq_resp = struct.unpack(HEADER_FORMAT, dados_resp[:HEADER_SIZE])
                    carga_resp = dados_resp[HEADER_SIZE:]

                    if id_resp != id_trans:
                        continue  # Pacote de outra transferência

                    if t_resp == TIPO_RESULTADO:
                        if espera_resultado:
                            return t_resp, id_resp, seq_resp, carga_resp
                        else:
                            status = carga_resp[0] if carga_resp else STATUS_ERRO
                            msg = carga_resp[1:].decode('utf-8', errors='replace') if len(carga_resp) > 1 else ""
                            raise OSError(f"Servidor abortou a transferência: status={status} msg='{msg}'")

                    if not espera_resultado and t_resp == TIPO_ACK and seq_resp == seq_esperada:
                        return t_resp, id_resp, seq_resp, carga_resp

                except socket.timeout:
                    break  # Timeout: sai do loop interno e retransmite

        raise TimeoutError(f"Servidor não respondeu após {MAX_TENTATIVAS} tentativas no pacote de sequência {seq_esperada}.")

    def enviar_arquivo(self, caminho_local: str, callback_progresso: Optional[Callable[[int, int], None]] = None) -> ResultadoUpload:
        """Envia um arquivo local ao servidor UDP.

        Args:
            caminho_local (str): Caminho do arquivo a ser enviado.
            callback_progresso (Optional[Callable[[int, int], None]]): Função callback para notificar (bytes_enviados, bytes_totais).

        Returns:
            ResultadoUpload: Resultado retornado pelo servidor.
        """
        if not os.path.isfile(caminho_local):
            raise FileNotFoundError(f"Arquivo local não encontrado: {caminho_local}")

        tamanho_total = os.path.getsize(caminho_local)
        nome_arquivo = os.path.basename(caminho_local)
        id_trans = random.randint(1, 0x7FFFFFFF)
        sha1 = hashlib.sha1()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if callback_progresso:
                callback_progresso(0, tamanho_total)

            # 1. INICIO (seq 0)
            nome_bytes = nome_arquivo.encode('utf-8')
            carga_inicio = struct.pack(">QH", tamanho_total, len(nome_bytes)) + nome_bytes
            self._enviar_e_aguardar(sock, id_trans, 0, TIPO_INICIO, carga_inicio, espera_resultado=False)

            # 2. DADOS (seq 1..N)
            total_blocos = (tamanho_total + 1023) // 1024 if tamanho_total > 0 else 0
            bytes_enviados = 0

            with open(caminho_local, "rb") as f:
                for seq in range(1, total_blocos + 1):
                    bloco = f.read(1024)
                    sha1.update(bloco)
                    self._enviar_e_aguardar(sock, id_trans, seq, TIPO_DADOS, bloco, espera_resultado=False)
                    bytes_enviados += len(bloco)
                    if callback_progresso:
                        callback_progresso(bytes_enviados, tamanho_total)

            # 3. FIM (seq N+1)
            seq_fim = total_blocos + 1
            carga_fim = sha1.digest()  # 20 bytes SHA-1
            _, _, _, carga_resultado = self._enviar_e_aguardar(sock, id_trans, seq_fim, TIPO_FIM, carga_fim, espera_resultado=True)

            status = carga_resultado[0] if carga_resultado else STATUS_ERRO
            msg = carga_resultado[1:].decode('utf-8', errors='replace') if len(carga_resultado) > 1 else ""
            return ResultadoUpload(status, msg)

        finally:
            sock.close()


def exibir_barra_progresso(enviados: int, totais: int) -> None:
    """Exibe uma barra de progresso visual no console.

    Args:
        enviados (int): Bytes já transmitidos e confirmados.
        totais (int): Tamanho total do arquivo em bytes.
    """
    pct = (enviados / totais * 100) if totais > 0 else 100.0
    largura = 30
    preenchido = int(largura * enviados // totais) if totais > 0 else largura
    barra = "█" * preenchido + "-" * (largura - preenchido)
    print(f"\r[{barra}] {pct:6.2f}% ({enviados}/{totais} bytes)", end="", flush=True)
    if enviados >= totais:
        print()


def menu() -> None:
    """Menu interativo para execução do cliente de upload via CLI."""
    host = SERVER_HOST
    port = SERVER_PORT

    while True:
        print(f"\n=== CLIENTE UDP UPLOAD ({host}:{port}) ===")
        print("1. Enviar Arquivo")
        print("2. Alterar Servidor (IP / Porta)")
        print("0. Sair")
        op = input("Escolha uma opção: ").strip()

        if op == "1":
            caminho = input("Caminho do arquivo local: ").strip()
            if not os.path.exists(caminho):
                print("Arquivo não encontrado.")
                continue

            print(f"Iniciando upload de '{os.path.basename(caminho)}' ({os.path.getsize(caminho)} bytes)...")
            cliente = ClienteUploadUDP(host, port)
            try:
                res = cliente.enviar_arquivo(caminho, callback_progresso=exibir_barra_progresso)
                if res.is_sucesso():
                    print(f"\n[SUCESSO] Servidor confirmou o recebimento: {res.mensagem}")
                else:
                    print(f"\n[FALHA] Servidor recusou ou encontrou erro (status={res.status}): {res.mensagem}")
            except Exception as e:
                print(f"\n[ERRO] Falha no upload: {e}")

        elif op == "2":
            h = input(f"Novo IP [{host}]: ").strip()
            p = input(f"Nova Porta [{port}]: ").strip()
            if h:
                host = h
            if p:
                port = int(p)
            print(f"Servidor alterado para {host}:{port}")

        elif op == "0":
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    menu()