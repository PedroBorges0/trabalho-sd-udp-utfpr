"""
Descrição: Servidor UDP de Upload de Arquivos (Questão 2 da Atividade 2 - UDP).
           O servidor escuta na porta UDP 6000 (padrão) e recebe arquivos divididos em blocos
           de até 1024 bytes utilizando o protocolo binário especificado:
             - INICIO (seq 0): Anúncio do nome e tamanho do arquivo.
             - DADOS (seq 1..N): Transferência em blocos de 1024 bytes.
             - FIM (seq N+1): Envio do checksum SHA-1 de 20 bytes para verificação de integridade.
           Características e Opcionais Implementados:
           - Suporta múltiplas transferências simultâneas concorrentes.
           - Confirma cada pacote com ACK (Stop-and-Wait / Parar-e-Esperar).
           - Sanitiza nomes contra vulnerabilidades de Path Traversal (ex: ../).
           - Trata duplicatas de arquivos sem sobrescrever (sufixos _1, _2...).
           - Registro de logs detalhado de auditoria no console e no arquivo 'servidor_upload.log'.
           - Limpeza automática de sessões inativas por mais de 30 segundos.
Autores: Daniel Suzuki Naves e Pedro Borges De Araujo
Data de criação: 07/10/2026
Última atualização: 09/10/2026
"""

import os
import sys
import time
import socket
import struct
import hashlib
import logging
import threading
from datetime import datetime
from typing import Dict, Tuple, Optional

# Constantes do Protocolo de Upload via UDP
PORTA_PADRAO = 6000
PASTA_PADRAO = "uploads_recebidos"
ARQUIVO_LOG_PADRAO = "servidor_upload.log"

TIPO_INICIO = 1
TIPO_DADOS = 2
TIPO_FIM = 3
TIPO_ACK = 4
TIPO_RESULTADO = 5

STATUS_OK = 0
STATUS_CHECKSUM_DIVERGENTE = 1
STATUS_ERRO = 2

HEADER_FORMAT = ">BII"  # tipo (1B), idTransferencia (4B), sequencia (4B)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 9 bytes
TAMANHO_BUFFER_UDP = 4096
INATIVIDADE_MAXIMA_SEG = 30.0


def sanitizar_nome_arquivo(nome_bruto: str) -> str:
    """Remove diretórios e caracteres perigosos para evitar Path Traversal.

    Args:
        nome_bruto (str): Nome do arquivo recebido da rede.

    Returns:
        str: Apenas o nome base do arquivo.

    Raises:
        ValueError: Se o nome for vazio ou inválido.
    """
    nome_limpo = os.path.basename(nome_bruto.strip().replace("\\", "/"))
    if not nome_limpo or nome_limpo in (".", ".."):
        raise ValueError("Nome de arquivo inválido.")
    return nome_limpo


def montar_caminho_candidato(pasta_destino: str, nome_base: str, indice: int) -> str:
    """Gera um caminho candidato adicionando sufixos (_1, _2...) para evitar sobrescrever.

    Args:
        pasta_destino (str): Diretório de destino.
        nome_base (str): Nome sanitizado do arquivo.
        indice (int): Sufixo numérico (0 para tentar o nome original).

    Returns:
        str: Caminho completo candidato.
    """
    if indice == 0:
        return os.path.join(pasta_destino, nome_base)

    nome_partes = os.path.splitext(nome_base)
    novo_nome = f"{nome_partes[0]}_{indice}{nome_partes[1]}"
    return os.path.join(pasta_destino, novo_nome)


class SessaoRecepcao:
    """Representa uma transferência de arquivo individual em andamento no servidor."""

    def __init__(self, origem: Tuple[str, int], id_trans: int, nome_arquivo: str, tamanho_arquivo: int, pasta_destino: str):
        """Inicializa a sessão de recepção do arquivo.

        Args:
            origem (Tuple[str, int]): Endereço IP e porta do cliente.
            id_trans (int): Identificador único da transferência.
            nome_arquivo (str): Nome sanitizado do arquivo.
            tamanho_arquivo (int): Tamanho total em bytes anunciado.
            pasta_destino (str): Diretório onde o arquivo será salvo.
        """
        self.origem = origem
        self.id_trans = id_trans
        self.nome_arquivo = nome_arquivo
        self.tamanho_arquivo = tamanho_arquivo
        self.pasta_destino = pasta_destino

        self.total_blocos = (tamanho_arquivo + 1023) // 1024 if tamanho_arquivo > 0 else 0
        self.proxima_sequencia = 1
        self.bytes_recebidos = 0

        self.inicio_dt = datetime.now()
        self.fim_dt: Optional[datetime] = None
        self.ultima_atividade = time.time()

        self.sha1 = hashlib.sha1()
        self.finalizada = False
        self.status = STATUS_ERRO
        self.mensagem_resultado = ""
        self.caminho_final = ""

        # Cria arquivo temporário .part
        os.makedirs(self.pasta_destino, exist_ok=True)
        self.caminho_part = os.path.join(
            self.pasta_destino, f"upload_{id_trans}_{int(time.time())}.part"
        )
        self.file_obj = open(self.caminho_part, "wb")

    def gravar_bloco(self, bloco: bytes) -> None:
        """Grava um bloco de dados no arquivo temporário e atualiza o SHA-1.

        Args:
            bloco (bytes): Conteúdo binário do bloco.
        """
        self.file_obj.write(bloco)
        self.sha1.update(bloco)
        self.bytes_recebidos += len(bloco)
        self.proxima_sequencia += 1
        self.ultima_atividade = time.time()

    def concluir(self, sha1_recebido: bytes) -> None:
        """Fecha o temporário, compara o SHA-1 e salva o arquivo final se íntegro.

        Args:
            sha1_recebido (bytes): Checksum de 20 bytes enviado pelo cliente.
        """
        self.file_obj.close()
        self.fim_dt = datetime.now()
        sha1_calculado = self.sha1.digest()

        integro = (
            self.bytes_recebidos == self.tamanho_arquivo and
            sha1_calculado == sha1_recebido
        )

        if integro:
            # Move do .part para o nome final sem sobrescrever
            idx = 0
            while True:
                candidato = montar_caminho_candidato(self.pasta_destino, self.nome_arquivo, idx)
                if not os.path.exists(candidato):
                    os.rename(self.caminho_part, candidato)
                    self.caminho_final = candidato
                    break
                idx += 1

            self.status = STATUS_OK
            self.mensagem_resultado = f"Arquivo salvo como {os.path.basename(self.caminho_final)} sha1={sha1_calculado.hex()}"
        else:
            if os.path.exists(self.caminho_part):
                os.remove(self.caminho_part)
            self.status = STATUS_CHECKSUM_DIVERGENTE
            self.mensagem_resultado = f"Checksum SHA-1 divergente (calculado {sha1_calculado.hex()}); arquivo descartado"

        self.finalizada = True

    def abortar(self) -> None:
        """Aborta a transferência e apaga o arquivo temporário."""
        try:
            self.file_obj.close()
            if os.path.exists(self.caminho_part):
                os.remove(self.caminho_part)
        except OSError:
            pass
        self.finalizada = True


class ServidorUploadUDP:
    """Servidor UDP de upload de arquivos com verificação SHA-1."""

    def __init__(self, porta_udp: int = PORTA_PADRAO, pasta_destino: str = PASTA_PADRAO, arquivo_log: str = ARQUIVO_LOG_PADRAO):
        """Inicializa as configurações do servidor.

        Args:
            porta_udp (int): Porta UDP em que o servidor escutará.
            pasta_destino (str): Diretório para armazenar os arquivos recebidos.
            arquivo_log (str): Caminho do arquivo de log de auditoria.
        """
        self.porta_udp = porta_udp
        self.pasta_destino = pasta_destino
        self.arquivo_log = arquivo_log

        self.socket_udp: Optional[socket.socket] = None
        self.sessoes: Dict[str, SessaoRecepcao] = {}
        self.trava_sessoes = threading.Lock()
        self.trava_log = threading.Lock()
        self.executando = False

    def registrar_log(self, mensagem: str) -> None:
        """Registra uma mensagem no console e no arquivo de log.

        Args:
            mensagem (str): Texto do evento de log.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        linha_completa = f"[{timestamp}] {mensagem}"
        print(linha_completa, flush=True)

        with self.trava_log:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.arquivo_log)), exist_ok=True)
                with open(self.arquivo_log, "a", encoding="utf-8") as f:
                    f.write(linha_completa + "\n")
            except OSError as erro:
                print(f"Erro ao escrever no arquivo de log: {erro}", file=sys.stderr)

    def enviar_pacote(self, destino: Tuple[str, int], tipo: int, id_trans: int, seq: int, carga: bytes = b"") -> None:
        """Codifica e envia um pacote UDP ao cliente.

        Args:
            destino (Tuple[str, int]): Endereço (IP, porta) do cliente.
            tipo (int): Tipo do pacote (ACK, RESULTADO, etc.).
            id_trans (int): ID da transferência.
            seq (int): Número de sequência.
            carga (bytes): Carga do pacote.
        """
        header = struct.pack(HEADER_FORMAT, tipo, id_trans, seq)
        datagrama = header + carga
        try:
            self.socket_udp.sendto(datagrama, destino)
        except OSError as e:
            self.registrar_log(f"ERRO ao enviar pacote para {destino}: {e}")

    def enviar_resultado(self, destino: Tuple[str, int], id_trans: int, seq: int, status: int, mensagem: str) -> None:
        """Envia um pacote RESULTADO ao cliente.

        Args:
            destino (Tuple[str, int]): Endereço do cliente.
            id_trans (int): ID da transferência.
            seq (int): Número de sequência.
            status (int): Código de status (0=OK, 1=CHECKSUM_DIVERGENTE, 2=ERRO).
            mensagem (str): Texto explicativo.
        """
        carga_res = struct.pack(">B", status) + mensagem.encode('utf-8')[:400]
        self.enviar_pacote(destino, TIPO_RESULTADO, id_trans, seq, carga_res)

    def tratar_pacote(self, dados: bytes, origem: Tuple[str, int]) -> None:
        """Decodifica e processa os pacotes UDP recebidos dos clientes.

        Args:
            dados (bytes): Bytes do datagrama lido.
            origem (Tuple[str, int]): Endereço IP e porta do cliente.
        """
        if len(dados) < HEADER_SIZE:
            return  # Ignora datagramas menores que o cabeçalho

        tipo, id_trans, seq = struct.unpack(HEADER_FORMAT, dados[:HEADER_SIZE])
        carga = dados[HEADER_SIZE:]
        chave_sessao = f"{origem[0]}:{origem[1]}/{id_trans}"

        if tipo == TIPO_INICIO:
            self.tratar_inicio(origem, id_trans, seq, carga, chave_sessao)
        elif tipo == TIPO_DADOS:
            self.tratar_dados(origem, id_trans, seq, carga, chave_sessao)
        elif tipo == TIPO_FIM:
            self.tratar_fim(origem, id_trans, seq, carga, chave_sessao)

    def tratar_inicio(self, origem: Tuple[str, int], id_trans: int, seq: int, carga: bytes, chave: str) -> None:
        """Processa o pacote INICIO (anúncio do arquivo)."""
        with self.trava_sessoes:
            if chave in self.sessoes:
                # Retransmissão do INICIO: apenas re-envia o ACK 0
                self.enviar_pacote(origem, TIPO_ACK, id_trans, 0)
                return

        if len(carga) < 10:
            self.enviar_resultado(origem, id_trans, 0, STATUS_ERRO, "Carga de INICIO invalida")
            return

        tam_arquivo, tam_nome = struct.unpack(">QH", carga[:10])
        if len(carga) < 10 + tam_nome:
            self.enviar_resultado(origem, id_trans, 0, STATUS_ERRO, "Nome de arquivo truncado")
            return

        nome_bruto = carga[10:10 + tam_nome].decode('utf-8', errors='replace')
        try:
            nome_seguro = sanitizar_nome_arquivo(nome_bruto)
        except ValueError as err:
            self.enviar_resultado(origem, id_trans, 0, STATUS_ERRO, str(err))
            return

        try:
            sessao = SessaoRecepcao(origem, id_trans, nome_seguro, tam_arquivo, self.pasta_destino)
            with self.trava_sessoes:
                self.sessoes[chave] = sessao

            self.registrar_log(
                f"INICIO horario={sessao.inicio_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} "
                f"origem={origem[0]}:{origem[1]} arquivo={nome_seguro} tamanho={tam_arquivo}"
            )
            self.enviar_pacote(origem, TIPO_ACK, id_trans, 0)
        except Exception as e:
            self.enviar_resultado(origem, id_trans, 0, STATUS_ERRO, f"Erro ao iniciar sessao: {e}")

    def tratar_dados(self, origem: Tuple[str, int], id_trans: int, seq: int, carga: bytes, chave: str) -> None:
        """Processa um bloco de DADOS do arquivo."""
        with self.trava_sessoes:
            sessao = self.sessoes.get(chave)

        if not sessao:
            self.enviar_resultado(origem, id_trans, seq, STATUS_ERRO, "Transferencia desconhecida")
            return

        if sessao.finalizada:
            self.enviar_resultado(origem, id_trans, seq, sessao.status, sessao.mensagem_resultado)
            return

        if seq < sessao.proxima_sequencia:
            # Duplicata já recebida: re-envia ACK
            self.enviar_pacote(origem, TIPO_ACK, id_trans, seq)
            return

        if seq > sessao.proxima_sequencia:
            return  # Fora de ordem: ignora para o cliente retransmitir

        try:
            sessao.gravar_bloco(carga)
            self.enviar_pacote(origem, TIPO_ACK, id_trans, seq)
        except Exception as e:
            sessao.abortar()
            self.enviar_resultado(origem, id_trans, seq, STATUS_ERRO, f"Erro de disco: {e}")

    def tratar_fim(self, origem: Tuple[str, int], id_trans: int, seq: int, carga: bytes, chave: str) -> None:
        """Processa o pacote FIM e conclui a verificação do arquivo."""
        with self.trava_sessoes:
            sessao = self.sessoes.get(chave)

        if not sessao:
            self.enviar_resultado(origem, id_trans, seq, STATUS_ERRO, "Transferencia desconhecida")
            return

        if sessao.finalizada:
            self.enviar_resultado(origem, id_trans, seq, sessao.status, sessao.mensagem_resultado)
            return

        if len(carga) != 20:
            sessao.abortar()
            self.enviar_resultado(origem, id_trans, seq, STATUS_ERRO, "Tamanho do checksum SHA-1 invalido")
            return

        sessao.concluir(sha1_recebido=carga)

        status_str = "OK" if sessao.status == STATUS_OK else ("CHECKSUM_DIVERGENTE" if sessao.status == STATUS_CHECKSUM_DIVERGENTE else "ERRO")
        salvo_como = f" salvo_como={os.path.basename(sessao.caminho_final)}" if sessao.caminho_final else ""

        self.registrar_log(
            f"FIM inicio={sessao.inicio_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} "
            f"fim={sessao.fim_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} "
            f"origem={origem[0]}:{origem[1]} arquivo={sessao.nome_arquivo} "
            f"tamanho={sessao.tamanho_arquivo} recebido={sessao.bytes_recebidos} "
            f"status={status_str}{salvo_como} detalhe=\"{sessao.mensagem_resultado}\""
        )

        self.enviar_resultado(origem, id_trans, seq, sessao.status, sessao.mensagem_resultado)

    def descartar_sessoes_inativas(self) -> None:
        """Remove sessões sem atividade há mais de 30 segundos."""
        agora = time.time()
        with self.trava_sessoes:
            para_remover = []
            for chave, sessao in self.sessoes.items():
                if (agora - sessao.ultima_atividade) > INATIVIDADE_MAXIMA_SEG:
                    if not sessao.finalizada:
                        sessao.abortar()
                        sessao.status = STATUS_ERRO
                        sessao.mensagem_resultado = "Abortada por inatividade"
                        self.registrar_log(f"FIM (Inatividade) origem={sessao.origem[0]}:{sessao.origem[1]} arquivo={sessao.nome_arquivo}")
                    para_remover.append(chave)

            for c in para_remover:
                del self.sessoes[c]

    def loop_limpeza(self) -> None:
        """Thread periódica de limpeza de sessões."""
        while self.executando:
            time.sleep(5)
            self.descartar_sessoes_inativas()

    def iniciar(self) -> None:
        """Inicia o socket UDP e o laço de recepção de arquivos."""
        os.makedirs(self.pasta_destino, exist_ok=True)
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_udp.bind(("0.0.0.0", self.porta_udp))
        self.executando = True

        threading.Thread(target=self.loop_limpeza, daemon=True).start()

        self.registrar_log(f"SERVIDOR UDP de Upload escutando na porta {self.porta_udp}, pasta: {os.path.abspath(self.pasta_destino)}")

        try:
            while self.executando:
                dados, origem = self.socket_udp.recvfrom(TAMANHO_BUFFER_UDP)
                if dados:
                    self.tratar_pacote(dados, origem)
        except OSError:
            if self.executando:
                raise

    def parar(self) -> None:
        """Encerra o servidor UDP."""
        self.executando = False
        if self.socket_udp:
            try:
                self.socket_udp.close()
            except OSError:
                pass


def main() -> None:
    """Ponto de entrada via CLI."""
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else PORTA_PADRAO
    pasta = sys.argv[2] if len(sys.argv) > 2 else PASTA_PADRAO
    arquivo_log = sys.argv[3] if len(sys.argv) > 3 else ARQUIVO_LOG_PADRAO

    servidor = ServidorUploadUDP(porta, pasta, arquivo_log)
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        print("\nServidor encerrado pelo usuário.")
        servidor.parar()


if __name__ == "__main__":
    main()