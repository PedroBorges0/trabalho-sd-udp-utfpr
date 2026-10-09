"""
Descrição: Servidor TCP que mantém a lista de participantes ativos no chat P2P
           (opcionais 1.a, 1.b e 1.c da Questão 1 da Atividade 2 - UDP).
           O servidor escuta na porta TCP 5000 (padrão) e aceita os comandos:
           - ENTRAR <apelido> <portaUdp>: registra o participante.
           - LISTAR: envia a lista de participantes ativos.
           - SAIR: remove o participante e fecha a conexão.
           Sempre que a lista de participantes muda (entrada ou saída),
           o servidor notifica automaticamente todos os clientes conectados.
Autores: Daniel Suzuki Naves e Pedro Borges De Araujo
Data de criação: 07/10/2026
Última atualização: 09/10/2026
"""

import logging
import socket
import threading
from typing import Dict, Tuple

# Configuração de logs no console
logging.basicConfig(
    level=logging.INFO,
    format="[servidor-lista] %(asctime)s - %(message)s",
    datefmt="%H:%M:%S"
)

# Porta TCP padrão
PORTA_PADRAO = 5000


class ServidorListaAtivos:
    """Servidor TCP para gerenciamento da lista de participantes ativos do Chat P2P."""

    def __init__(self, porta_tcp: int = PORTA_PADRAO):
        """Inicializa as estruturas do servidor.

        Args:
            porta_tcp (int): Porta TCP em que o servidor escutará.
        """
        self.porta_tcp = porta_tcp
        self.sessoes: Dict[str, Tuple[str, int, socket.socket, threading.Lock]] = {}
        self.trava_sessoes = threading.Lock()
        self.executando = False
        self.server_socket = None

    def montar_mensagem_lista(self) -> str:
        """Monta a string da mensagem LISTA com todos os participantes ativos.

        Returns:
            str: Texto formatado com 'LISTA n\n' seguido das linhas 'apelido ip portaUdp\n'.
        """
        with self.trava_sessoes:
            linhas = [f"LISTA {len(self.sessoes)}"]
            for apelido, (ip, porta_udp, _, _) in self.sessoes.items():
                linhas.append(f"{apelido} {ip} {porta_udp}")
            return "\n".join(linhas) + "\n"

    def notificar_todos(self) -> None:
        """Envia a lista atualizada a todos os participantes conectados."""
        mensagem = self.montar_mensagem_lista()
        with self.trava_sessoes:
            sessoes_copia = list(self.sessoes.values())

        for _, _, sock_cli, trava_cli in sessoes_copia:
            try:
                with trava_cli:
                    sock_cli.sendall(mensagem.encode('utf-8'))
            except OSError:
                pass  # Conexão quebrada tratada na thread do cliente

    def atender_cliente(self, sock_cli: socket.socket, addr_cli: Tuple[str, int]) -> None:
        """Atende individualmente a conexão TCP de cada cliente.

        Args:
            sock_cli (socket.socket): Socket do cliente conectado.
            addr_cli (Tuple[str, int]): Endereço IP e porta TCP do cliente.
        """
        ip_cliente = addr_cli[0]
        apelido_registrado = None
        trava_escrita = threading.Lock()

        try:
            rfile = sock_cli.makefile('r', encoding='utf-8')

            # 1. Processa o comando inicial ENTRAR
            primeira_linha = rfile.readline()
            if not primeira_linha:
                return

            partes = primeira_linha.strip().split()
            if len(partes) != 3 or partes[0].upper() != "ENTRAR":
                sock_cli.sendall("ERRO use: ENTRAR <apelido> <portaUdp>\n".encode('utf-8'))
                return

            apelido = partes[1]
            try:
                porta_udp = int(partes[2])
            except ValueError:
                sock_cli.sendall("ERRO porta UDP invalida\n".encode('utf-8'))
                return

            tam_apelido = len(apelido.encode('utf-8'))
            if tam_apelido < 1 or tam_apelido > 64:
                sock_cli.sendall("ERRO apelido deve ter de 1 a 64 bytes\n".encode('utf-8'))
                return

            if not (1 <= porta_udp <= 65535):
                sock_cli.sendall("ERRO porta UDP fora do intervalo 1-65535\n".encode('utf-8'))
                return

            with self.trava_sessoes:
                if apelido in self.sessoes:
                    sock_cli.sendall("ERRO apelido ja esta em uso\n".encode('utf-8'))
                    return
                sock_cli.sendall("OK\n".encode('utf-8'))
                self.sessoes[apelido] = (ip_cliente, porta_udp, sock_cli, trava_escrita)
                apelido_registrado = apelido

            logging.info(f"Entrou: {apelido} ({ip_cliente}:{porta_udp})")
            self.notificar_todos()

            # 2. Loop de escuta dos comandos subsequentes (LISTAR, SAIR)
            for linha in rfile:
                cmd = linha.strip().upper()
                if cmd == "LISTAR":
                    msg_lista = self.montar_mensagem_lista()
                    with trava_escrita:
                        sock_cli.sendall(msg_lista.encode('utf-8'))
                elif cmd == "SAIR":
                    break
                elif cmd:
                    with trava_escrita:
                        sock_cli.sendall("ERRO comando desconhecido\n".encode('utf-8'))

        except (OSError, UnicodeDecodeError):
            pass
        finally:
            if apelido_registrado:
                with self.trava_sessoes:
                    if apelido_registrado in self.sessoes:
                        del self.sessoes[apelido_registrado]
                logging.info(f"Saiu: {apelido_registrado}")
                self.notificar_todos()
            try:
                sock_cli.close()
            except OSError:
                pass

    def iniciar(self) -> None:
        """Inicia a escuta de conexões TCP na porta configurada."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.porta_tcp))
        self.server_socket.listen(10)
        self.executando = True

        logging.info(f"Escutando na porta TCP {self.porta_tcp}...")

        try:
            while self.executando:
                sock_cli, addr_cli = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.atender_cliente,
                    args=(sock_cli, addr_cli),
                    daemon=True
                )
                thread.start()
        except OSError:
            if self.executando:
                raise

    def parar(self) -> None:
        """Encerra o servidor e fecha os sockets ativos."""
        self.executando = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass


def main() -> None:
    """Ponto de entrada para execução do servidor da lista de ativos via CLI."""
    import sys
    porta = int(sys.argv[1]) if len(sys.argv) > 1 else PORTA_PADRAO
    servidor = ServidorListaAtivos(porta)
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        logging.info("Servidor encerrado pelo usuário.")
        servidor.parar()


if __name__ == "__main__":
    main()