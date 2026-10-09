"""
Descrição: Cliente Peer-to-Peer (P2P) para o Chat UDP (Questão 1 da Atividade 2 - UDP).
           Cada instância:
           - Abre um Socket UDP na porta local especificada para trocar datagramas com outros peers.
           - Registra apelido + porta UDP no Servidor TCP de Lista de Ativos (ServidorListaAtivos).
           - Recebe notificações em tempo real do Servidor TCP quando novos peers entram ou saem.
           - Envia e recebe mensagens dos tipos: 1 (Normal), 2 (Emoji), 3 (URL) e 4 (ECHO).
           - Monitora conectividade via mensagens ECHO periódicas de keep-alive.
Autores: Daniel Suzuki Naves e Pedro Borges De Araujo
Data de criação: 07/10/2026
Última atualização: 09/10/2026
"""

import sys
import time
import socket
import threading
from urllib.parse import urlparse
from typing import Dict, Tuple, Set

# Constantes dos Tipos de Mensagem do Protocolo UDP (Atividade 2)
TIPO_NORMAL = 1
TIPO_EMOJI = 2
TIPO_URL = 3
TIPO_ECHO = 4

INTERVALO_ECHO_SEG = 5
LIMITE_SEM_RESPOSTA_ECHO_SEG = 15
TAMANHO_BUFFER_UDP = 512

# Dicionário de Emojis Suportados (Substituição por Ícones Unicode)
MAPA_EMOJIS = {
    "feliz": "😊",
    "triste": "😢",
    "rindo": "😂",
    "coracao": "❤️",
    "joinha": "👍",
    "fogo": "🔥",
    "festa": "🎉",
    "duvida": "🤔",
    "piscada": "😉",
    "oculos": "😎"
}


def substituir_emojis(texto: str) -> str:
    """Substitui atalhos do tipo :nome: pelos equivalentes Unicode em MAPA_EMOJIS.

    Args:
        texto (str): Texto contendo potenciais atalhos de emoji.

    Returns:
        str: Texto com atalhos substituídos por símbolos de emoji.
    """
    for nome, icone in MAPA_EMOJIS.items():
        texto = texto.replace(f":{nome}:", icone)
    return texto


def codificar_mensagem(tipo: int, apelido: str, texto: str) -> bytes:
    """Codifica uma mensagem no formato binário definido na especificação da Atividade 2.

    Estrutura:
      [1 byte: tipo] [1 byte: tam_apl] [N bytes: apelido] [1 byte: tam_msg] [M bytes: mensagem]

    Args:
        tipo (int): Tipo da mensagem (1..4).
        apelido (str): Apelido do remetente (1 a 64 bytes UTF-8).
        texto (str): Conteúdo da mensagem (0 a 255 bytes UTF-8).

    Returns:
        bytes: Pacote de datagrama codificado.
    """
    nick_bytes = apelido.encode('utf-8')
    if not (1 <= len(nick_bytes) <= 64):
        raise ValueError("Apelido deve ter de 1 a 64 bytes em UTF-8.")

    msg_bytes = texto.encode('utf-8')
    if len(msg_bytes) > 255:
        msg_bytes = msg_bytes[:255]  # Truncamento de segurança

    buffer = bytearray()
    buffer.append(tipo & 0xFF)
    buffer.append(len(nick_bytes) & 0xFF)
    buffer.extend(nick_bytes)
    buffer.append(len(msg_bytes) & 0xFF)
    buffer.extend(msg_bytes)
    return bytes(buffer)


def decodificar_mensagem(dados: bytes) -> Tuple[int, str, str]:
    """Decodifica um datagrama UDP recebido.

    Args:
        dados (bytes): Bytes brutos do datagrama.

    Returns:
        Tuple[int, str, str]: (tipo, apelido, texto).

    Raises:
        ValueError: Se o datagrama estiver malformado ou incompleto.
    """
    if len(dados) < 3:
        raise ValueError("Datagrama menor que o tamanho mínimo de cabeçalho.")

    tipo = dados[0]
    tam_apl = dados[1]

    if len(dados) < 2 + tam_apl + 1:
        raise ValueError("Datagrama truncado na seção de apelido.")

    apelido = dados[2:2 + tam_apl].decode('utf-8', errors='replace')

    offset_tam_msg = 2 + tam_apl
    tam_msg = dados[offset_tam_msg]

    if len(dados) < offset_tam_msg + 1 + tam_msg:
        raise ValueError("Datagrama truncado no corpo da mensagem.")

    texto = dados[offset_tam_msg + 1:offset_tam_msg + 1 + tam_msg].decode('utf-8', errors='replace')
    return tipo, apelido, texto


class ChatPeer:
    """Participante (Peer) do Chat P2P com suporte a Sockets UDP e lista TCP."""

    def __init__(self, apelido: str, porta_udp: int, host_servidor: str = "localhost", porta_servidor: int = 5000):
        """Inicializa os parâmetros do peer.

        Args:
            apelido (str): Apelido deste participante no chat.
            porta_udp (int): Porta UDP local para escutar datagramas.
            host_servidor (str): Host IP do servidor TCP da lista de ativos.
            porta_servidor (int): Porta TCP do servidor da lista de ativos.
        """
        self.apelido = apelido
        self.porta_udp = porta_udp
        self.host_servidor = host_servidor
        self.porta_servidor = porta_servidor

        self.socket_udp: socket.socket = None
        self.socket_tcp: socket.socket = None
        self.executando = False

        # Mapa de peers ativos por apelido: apelido -> (ip, porta_udp)
        self.peers_ativos: Dict[str, Tuple[str, int]] = {}
        self.trava_peers = threading.Lock()

        # Rastreamento de timestamps de ECHO: "ip:porta" -> timestamp_seg
        self.ultimo_echo: Dict[str, float] = {}
        self.sem_resposta_notificados: Set[str] = set()

    def imprimir(self, texto: str) -> None:
        """Exibe uma mensagem no console de forma limpa."""
        print(texto, flush=True)

    def conectar_servidor(self) -> None:
        """Conecta ao servidor TCP da lista de ativos e efetua o registro."""
        self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_tcp.connect((self.host_servidor, self.porta_servidor))

        rfile = self.socket_tcp.makefile('r', encoding='utf-8')
        cmd = f"ENTRAR {self.apelido} {self.porta_udp}\n"
        self.socket_tcp.sendall(cmd.encode('utf-8'))

        # Lê resposta do registro
        resposta = rfile.readline()
        if not resposta:
            raise OSError("Servidor encerrou a conexão durante o registro.")

        resposta = resposta.strip()
        if resposta == "OK":
            return
        elif resposta.startswith("ERRO"):
            raise OSError(f"Servidor recusou registro: {resposta}")
        else:
            raise OSError(f"Resposta inesperada do servidor: {resposta}")

    def escutar_servidor_tcp(self) -> None:
        """Thread responsável por escutar atualizações 'LISTA' do servidor TCP."""
        try:
            rfile = self.socket_tcp.makefile('r', encoding='utf-8')
            while self.executando:
                linha = rfile.readline()
                if not linha:
                    if self.executando:
                        self.imprimir("[sistema] Conexão com o servidor de lista encerrada.")
                    break

                linha = linha.strip()
                if linha.startswith("LISTA "):
                    try:
                        qtd = int(linha.split()[1])
                        novos_peers: Dict[str, Tuple[str, int]] = {}
                        for _ in range(qtd):
                            linha_peer = rfile.readline()
                            if not linha_peer:
                                break
                            campos = linha_peer.strip().split()
                            if len(campos) == 3:
                                ap, ip, port = campos[0], campos[1], int(campos[2])
                                if ap != self.apelido:
                                    novos_peers[ap] = (ip, port)

                        self.atualizar_lista_peers(novos_peers)
                    except ValueError:
                        pass
        except OSError:
            if self.executando:
                self.imprimir("[sistema] Erro na escuta do servidor TCP.")

    def atualizar_lista_peers(self, novos_peers: Dict[str, Tuple[str, int]]) -> None:
        """Atualiza a lista interna de peers e notifica sobre entradas/saídas.

        Args:
            novos_peers (Dict[str, Tuple[str, int]]): Dicionário com os novos peers.
        """
        with self.trava_peers:
            anteriores = set(self.peers_ativos.keys())
            atuais = set(novos_peers.keys())

            entrantes = atuais - anteriores
            saindo = anteriores - atuais

            agora = time.time()
            for ap in entrantes:
                ip, port = novos_peers[ap]
                chave = f"{ip}:{port}"
                self.ultimo_echo[chave] = agora
                self.imprimir(f"[sistema] {ap} entrou no chat.")

            for ap in saindo:
                self.sem_resposta_notificados.discard(ap)
                self.imprimir(f"[sistema] {ap} saiu do chat.")

            self.peers_ativos = novos_peers

    def receber_datagramas_udp(self) -> None:
        """Thread responsável por receber e processar os datagramas UDP."""
        while self.executando:
            try:
                dados, addr = self.socket_udp.recvfrom(TAMANHO_BUFFER_UDP)
                if not dados:
                    continue
                self.tratar_datagrama_udp(dados, addr)
            except OSError:
                if self.executando:
                    break

    def tratar_datagrama_udp(self, dados: bytes, addr: Tuple[str, int]) -> None:
        """Mapeia e processa cada tipo de mensagem UDP recebida.

        Args:
            dados (bytes): Dados brutos do datagrama.
            addr (Tuple[str, int]): Endereço do remetente (IP, porta).
        """
        try:
            tipo, apelido, texto = decodificar_mensagem(dados)
        except ValueError:
            return  # Ignora datagramas malformados

        if tipo == TIPO_NORMAL:
            self.imprimir(f"[{apelido}] {texto}")
        elif tipo == TIPO_EMOJI:
            self.imprimir(f"[{apelido}] {texto}")
        elif tipo == TIPO_URL:
            self.imprimir(f"[{apelido}] compartilhou um link: {texto}")
        elif tipo == TIPO_ECHO:
            self.tratar_echo(apelido, texto, dados, addr)

    def tratar_echo(self, apelido_msg: str, texto: str, dados_originais: bytes, addr: Tuple[str, int]) -> None:
        """Trata o mecanismo de keep-alive ECHO (Tipo 4).

        Args:
            apelido_msg (str): Apelido contido na mensagem ECHO.
            texto (str): Conteúdo do texto do ECHO.
            dados_originais (bytes): Bytes brutos do datagrama recebido.
            addr (Tuple[str, int]): Endereço do remetente do datagrama.
        """
        ip, port = addr
        chave = f"{ip}:{port}"

        if apelido_msg == self.apelido:
            # Resposta de um ECHO que NÓS enviamos: o peer 'chave' está ativo!
            self.ultimo_echo[chave] = time.time()
        else:
            # ECHO vindo de outro peer: devolve a MESMA mensagem para ele confirmar
            try:
                self.socket_udp.sendto(dados_originais, addr)
            except OSError:
                pass

    def monitorar_echo(self) -> None:
        """Thread periódica para envio de ECHO e detecção de inatividade de peers."""
        while self.executando:
            time.sleep(INTERVALO_ECHO_SEG)
            if not self.executando:
                break

            # Envia ECHO para todos os peers conhecidos
            try:
                pacote_echo = codificar_mensagem(TIPO_ECHO, self.apelido, "echo")
                self.enviar_para_todos(pacote_echo)
            except Exception:
                pass

            agora = time.time()
            with self.trava_peers:
                for ap, (ip, port) in list(self.peers_ativos.items()):
                    chave = f"{ip}:{port}"
                    u_resp = self.ultimo_echo.get(chave, 0)
                    sem_resp = (agora - u_resp) > LIMITE_SEM_RESPOSTA_ECHO_SEG

                    if sem_resp and ap not in self.sem_resposta_notificados:
                        self.sem_resposta_notificados.add(ap)
                        self.imprimir(f"[aviso] {ap} não responde ao ECHO (pode estar inativo).")
                    elif not sem_resp and ap in self.sem_resposta_notificados:
                        self.sem_resposta_notificados.remove(ap)
                        self.imprimir(f"[sistema] {ap} voltou a responder ao ECHO.")

    def enviar_para_todos(self, dados_pacote: bytes) -> None:
        """Transmite um datagrama UDP para todos os peers ativos conhecidos.

        Args:
            dados_pacote (bytes): Datagrama codificado a ser transmitido.
        """
        with self.trava_peers:
            destinatarios = list(self.peers_ativos.values())

        for ip, port in destinatarios:
            try:
                self.socket_udp.sendto(dados_pacote, (ip, port))
            except OSError:
                pass

    def enviar_texto(self, tipo: int, texto: str) -> None:
        """Formata, envia e exibe localmente uma mensagem de texto.

        Args:
            tipo (int): Tipo da mensagem (TIPO_NORMAL, TIPO_EMOJI ou TIPO_URL).
            texto (str): Texto a ser enviado.
        """
        texto_ajustado = texto
        if len(texto.encode('utf-8')) > 255:
            self.imprimir("[aviso] Mensagem truncada para 255 bytes (limite do protocolo).")

        pacote = codificar_mensagem(tipo, self.apelido, texto_ajustado)

        with self.trava_peers:
            sem_peers = len(self.peers_ativos) == 0

        if sem_peers:
            self.imprimir("[sistema] Nenhum outro participante ativo no momento.")

        self.enviar_para_todos(pacote)
        self.imprimir(f"[você] {texto_ajustado}")

    def iniciar(self) -> None:
        """Inicia a execução completa do Peer (Socket UDP, registro TCP e threads)."""
        # Valida apelido antecipadamente
        codificar_mensagem(TIPO_NORMAL, self.apelido, "")

        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_udp.bind(("0.0.0.0", self.porta_udp))

        self.conectar_servidor()
        self.executando = True

        # Inicia threads auxiliares
        threading.Thread(target=self.receber_datagramas_udp, daemon=True).start()
        threading.Thread(target=self.escutar_servidor_tcp, daemon=True).start()
        threading.Thread(target=self.monitorar_echo, daemon=True).start()

        self.imprimir(f"[sistema] Conectado como '{self.apelido}' (UDP {self.porta_udp}). Digite /ajuda para ver os comandos.")
        self.executar_console()
        self.encerrar()

    def executar_console(self) -> None:
        """Loop interativo de leitura de comandos do teclado do usuário."""
        try:
            for linha in sys.stdin:
                linha = linha.strip()
                if not linha:
                    continue
                if not self.processar_entrada(linha):
                    break
        except KeyboardInterrupt:
            pass

    def processar_entrada(self, linha: str) -> bool:
        """Interpreta comandos iniciados por '/' ou mensagens normais.

        Args:
            linha (str): Entrada fornecida pelo usuário.

        Returns:
            bool: False se o usuário solicitou sair, True caso contrário.
        """
        if not linha.startswith("/"):
            texto_com_emojis = substituir_emojis(linha)
            self.enviar_texto(TIPO_NORMAL, texto_com_emojis)
            return True

        partes = linha.split(maxsplit=1)
        comando = partes[0].lower()
        arg = partes[1].strip() if len(partes) > 1 else ""

        if comando == "/sair":
            return False
        elif comando == "/lista":
            with self.trava_peers:
                if not self.peers_ativos:
                    self.imprimir("[sistema] Ninguém mais está no chat.")
                else:
                    self.imprimir("[sistema] Participantes ativos:")
                    for ap, (ip, port) in self.peers_ativos.items():
                        self.imprimir(f"   - {ap} ({ip}:{port})")
        elif comando == "/ativos":
            agora = time.time()
            with self.trava_peers:
                for ap, (ip, port) in self.peers_ativos.items():
                    chave = f"{ip}:{port}"
                    u_resp = self.ultimo_echo.get(chave, 0)
                    segs = int(agora - u_resp)
                    sit = "SEM RESPOSTA" if ap in self.sem_resposta_notificados else "ativo"
                    self.imprimir(f"   - {ap}: {sit} (último ECHO há {segs} s)")
        elif comando == "/emojis":
            lista_nomes = ", ".join([f":{k}: ({v})" for k, v in MAPA_EMOJIS.items()])
            self.imprimir(f"[sistema] Emojis disponíveis: {lista_nomes}")
        elif comando == "/emoji":
            if arg.lower() in MAPA_EMOJIS:
                self.enviar_texto(TIPO_EMOJI, MAPA_EMOJIS[arg.lower()])
            else:
                self.imprimir("[sistema] Emoji desconhecido. Use /emojis para ver a lista.")
        elif comando == "/url":
            if arg.startswith("http://") or arg.startswith("https://"):
                self.enviar_texto(TIPO_URL, arg)
            else:
                self.imprimir("[sistema] URL inválida. Exemplo: /url https://www.utfpr.edu.br")
        elif comando == "/ajuda":
            self.imprimir("[ajuda] Texto livre = mensagem normal (aceita :feliz:, :joinha:, etc.)")
            self.imprimir("[ajuda] /emoji <nome> | /emojis | /url <link> | /lista | /ativos | /sair")
        else:
            self.imprimir("[sistema] Comando desconhecido. Digite /ajuda.")

        return True

    def encerrar(self) -> None:
        """Encerra com segurança os sockets e desconecta do servidor TCP."""
        self.executando = False
        if self.socket_tcp:
            try:
                self.socket_tcp.sendall("SAIR\n".encode('utf-8'))
                self.socket_tcp.close()
            except OSError:
                pass
        if self.socket_udp:
            try:
                self.socket_udp.close()
            except OSError:
                pass


def main() -> None:
    """Ponto de entrada via linha de comando."""
    if len(sys.argv) < 3:
        print("Uso: python q1_chat_peer.py <apelido> <portaUdp> [hostServidor] [portaServidor]")
        sys.exit(1)

    apelido = sys.argv[1]
    porta_udp = int(sys.argv[2])
    host = sys.argv[3] if len(sys.argv) > 3 else "localhost"
    porta_tcp = int(sys.argv[4]) if len(sys.argv) > 4 else 5000

    peer = ChatPeer(apelido, porta_udp, host, porta_tcp)
    try:
        peer.iniciar()
    except Exception as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()