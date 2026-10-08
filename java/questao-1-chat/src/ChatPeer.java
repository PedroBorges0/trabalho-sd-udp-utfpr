/*
 * Arquivo....: ChatPeer.java
 * Descrição..: Cliente do chat P2P (Questão 1). Cada instância:
 *              - abre um socket UDP e recebe mensagens diretamente dos outros peers;
 *              - registra apelido + porta UDP no servidor TCP (ServidorListaAtivos) e
 *                recebe dele a lista de participantes ativos (opcionais 1.a, 1.b, 1.c);
 *              - envia cada mensagem digitada por UDP diretamente a todos os peers;
 *              - envia ECHO (tipo 4) periodicamente e responde aos ECHOs recebidos,
 *                indicando que está ativo;
 *              - suporta emojis por ícones (opcional 1.d).
 *
 *              ECHO: o peer A envia {tipo 4, apelido "A", texto}. O peer B devolve a MESMA
 *              mensagem (apelido continua "A"). Ao receber um ECHO com o próprio apelido,
 *              A sabe que B está ativo e não responde de novo (evita laço infinito).
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package chat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Participante (peer) do chat P2P.
 */
public class ChatPeer {

    /** Intervalo entre rodadas de ECHO enviadas aos peers, em milissegundos. */
    private static final int INTERVALO_ECHO_MS = 5000;
    /** Tempo sem resposta a ECHO após o qual o peer é considerado inativo, em milissegundos. */
    private static final int LIMITE_SEM_RESPOSTA_ECHO_MS = 15000;
    /** Tamanho do buffer de recepção UDP (maior que o maior datagrama válido, 322 bytes). */
    private static final int TAMANHO_BUFFER_RECEBIMENTO_BYTES = 512;
    private static final String TEXTO_DO_ECHO = "echo";

    private final String apelido;
    private final int portaUdp;
    private final String hostServidor;
    private final int portaServidor;

    private DatagramSocket socketUdp;
    private Socket socketServidor;
    private BufferedReader leitorServidor;
    private BufferedWriter escritorServidor;

    /** Peers conhecidos por apelido (mapa imutável substituído a cada LISTA recebida). */
    private volatile Map<String, PeerRemoto> peersAtivosPorApelido = Collections.emptyMap();
    /** Instante (ms) do último ECHO respondido, por chave "ip:porta". */
    private final Map<String, Long> ultimoEchoPorEndereco = new ConcurrentHashMap<>();
    /** Apelidos já avisados como sem resposta (para não repetir o aviso). */
    private final Set<String> apelidosSemResposta = ConcurrentHashMap.newKeySet();

    private volatile boolean executando;
    private final PrintStream saida =
            new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);

    /**
     * @param apelido       apelido deste participante (1 a 64 bytes, sem espaços)
     * @param portaUdp      porta UDP local para receber mensagens
     * @param hostServidor  nome ou IP do servidor TCP da lista de ativos
     * @param portaServidor porta TCP do servidor
     */
    public ChatPeer(String apelido, int portaUdp, String hostServidor, int portaServidor) {
        this.apelido = apelido;
        this.portaUdp = portaUdp;
        this.hostServidor = hostServidor;
        this.portaServidor = portaServidor;
    }

    /**
     * Inicia o peer: abre o UDP, registra no servidor, dispara as threads de apoio e
     * entra no laço de leitura do teclado (retorna quando o usuário digitar /sair).
     *
     * @throws IOException se o UDP não puder ser aberto ou o servidor recusar o registro
     */
    public void iniciar() throws IOException {
        new MensagemChat(MensagemChat.TIPO_NORMAL, apelido, ""); // valida o apelido cedo
        socketUdp = new DatagramSocket(portaUdp);
        try {
            conectarAoServidor();
        } catch (IOException erro) {
            encerrar();
            throw erro;
        }
        executando = true;
        iniciarThread("receptor-udp", this::receberDatagramas);
        iniciarThread("escuta-servidor", this::escutarServidor);
        iniciarThread("monitor-echo", this::monitorarEcho);

        imprimir("[sistema] conectado como '" + apelido + "' (UDP " + portaUdp + "). Digite /ajuda.");
        executarConsole();
        encerrar();
    }

    /**
     * Abre a conexão TCP, envia ENTRAR e aguarda OK ou ERRO. Listas que chegarem
     * antes do OK também são processadas.
     *
     * @throws IOException se a conexão falhar ou o servidor responder ERRO
     */
    private void conectarAoServidor() throws IOException {
        socketServidor = new Socket(hostServidor, portaServidor);
        leitorServidor = new BufferedReader(
                new InputStreamReader(socketServidor.getInputStream(), StandardCharsets.UTF_8));
        escritorServidor = new BufferedWriter(
                new OutputStreamWriter(socketServidor.getOutputStream(), StandardCharsets.UTF_8));

        escritorServidor.write("ENTRAR " + apelido + " " + portaUdp + "\n");
        escritorServidor.flush();

        String resposta;
        while ((resposta = processarProximaRespostaDoServidor()) != null) {
            if (resposta.equals("OK")) {
                return;
            }
            if (resposta.startsWith("ERRO")) {
                throw new IOException("Servidor recusou o registro: " + resposta);
            }
        }
        throw new IOException("Servidor encerrou a conexão durante o registro");
    }

    /**
     * Lê uma linha do servidor TCP. Se for "LISTA n", consome também as n linhas
     * seguintes e atualiza a lista de peers.
     *
     * @return a primeira linha lida ("OK", "ERRO ...", "LISTA n"), ou {@code null} no fim da conexão
     * @throws IOException se a conexão falhar ou a lista vier malformada
     */
    private String processarProximaRespostaDoServidor() throws IOException {
        String linha = leitorServidor.readLine();
        if (linha != null && linha.startsWith("LISTA ")) {
            try {
                int quantidade = Integer.parseInt(linha.substring(6).trim());
                Map<String, PeerRemoto> novaLista = new HashMap<>();
                for (int i = 0; i < quantidade; i++) {
                    String[] campos = leitorServidor.readLine().trim().split("\\s+");
                    PeerRemoto peer = new PeerRemoto(campos[0], InetAddress.getByName(campos[1]),
                            Integer.parseInt(campos[2]));
                    if (!peer.getApelido().equals(apelido)) {
                        novaLista.put(peer.getApelido(), peer);
                    }
                }
                atualizarListaDePeers(novaLista);
            } catch (RuntimeException formatoInvalido) {
                throw new IOException("Lista inválida recebida do servidor", formatoInvalido);
            }
        }
        return linha;
    }

    /**
     * Substitui a lista de peers e avisa o usuário de quem entrou ou saiu.
     *
     * @param novaLista lista recebida do servidor (sem este participante)
     */
    private void atualizarListaDePeers(Map<String, PeerRemoto> novaLista) {
        Map<String, PeerRemoto> listaAnterior = peersAtivosPorApelido;
        long agora = System.currentTimeMillis();
        for (PeerRemoto peer : novaLista.values()) {
            if (!listaAnterior.containsKey(peer.getApelido())) {
                ultimoEchoPorEndereco.put(peer.getChaveEndereco(), agora);
                imprimir("[sistema] " + peer.getApelido() + " entrou no chat");
            }
        }
        for (PeerRemoto peer : listaAnterior.values()) {
            if (!novaLista.containsKey(peer.getApelido())) {
                ultimoEchoPorEndereco.remove(peer.getChaveEndereco());
                apelidosSemResposta.remove(peer.getApelido());
                imprimir("[sistema] " + peer.getApelido() + " saiu do chat");
            }
        }
        peersAtivosPorApelido = Collections.unmodifiableMap(novaLista);
    }

    /** Thread que continua lendo as notificações de lista enviadas pelo servidor (1.c). */
    private void escutarServidor() {
        try {
            while (executando) {
                String linha = processarProximaRespostaDoServidor();
                if (linha == null) {
                    if (executando) {
                        imprimir("[sistema] conexão com o servidor encerrada");
                    }
                    return;
                }
            }
        } catch (IOException erro) {
            if (executando) {
                imprimir("[sistema] erro na conexão com o servidor: " + erro.getMessage());
            }
        }
    }

    /** Thread que recebe datagramas UDP e os encaminha para tratamento. */
    private void receberDatagramas() {
        byte[] buffer = new byte[TAMANHO_BUFFER_RECEBIMENTO_BYTES];
        while (executando) {
            DatagramPacket pacote = new DatagramPacket(buffer, buffer.length);
            try {
                socketUdp.receive(pacote);
            } catch (IOException erro) {
                if (executando) {
                    imprimir("[sistema] erro ao receber datagrama: " + erro.getMessage());
                }
                return;
            }
            tratarDatagrama(pacote);
        }
    }

    /**
     * Decodifica um datagrama e age conforme o tipo: exibe mensagens ou trata ECHO.
     *
     * @param pacote datagrama recém-recebido
     */
    private void tratarDatagrama(DatagramPacket pacote) {
        MensagemChat mensagem;
        try {
            mensagem = MensagemChat.decodificar(pacote.getData(), pacote.getLength());
        } catch (IllegalArgumentException malformado) {
            imprimir("[aviso] datagrama inválido ignorado de " + pacote.getAddress().getHostAddress());
            return;
        }
        switch (mensagem.getTipo()) {
            case MensagemChat.TIPO_NORMAL:
                imprimir("[" + mensagem.getApelido() + "] " + mensagem.getTexto());
                break;
            case MensagemChat.TIPO_EMOJI:
                imprimir("[" + mensagem.getApelido() + "] " + mensagem.getTexto());
                break;
            case MensagemChat.TIPO_URL:
                imprimir("[" + mensagem.getApelido() + "] compartilhou um link: " + mensagem.getTexto());
                break;
            case MensagemChat.TIPO_ECHO:
                tratarEcho(mensagem, pacote);
                break;
            default:
                break;
        }
    }

    /**
     * Trata um ECHO: se for de outro peer, devolve a mesma mensagem; se for a volta de
     * um ECHO nosso, registra que o peer de origem do datagrama está ativo.
     *
     * @param mensagem mensagem de ECHO decodificada
     * @param pacote   datagrama original (origem usada para responder)
     */
    private void tratarEcho(MensagemChat mensagem, DatagramPacket pacote) {
        if (mensagem.getApelido().equals(apelido)) {
            String chave = pacote.getAddress().getHostAddress() + ":" + pacote.getPort();
            ultimoEchoPorEndereco.put(chave, System.currentTimeMillis());
            return;
        }
        try {
            DatagramPacket resposta = new DatagramPacket(
                    pacote.getData(), pacote.getLength(), pacote.getSocketAddress());
            socketUdp.send(resposta);
        } catch (IOException erro) {
            imprimir("[aviso] falha ao responder ECHO: " + erro.getMessage());
        }
    }

    /** Thread que envia ECHO aos peers periodicamente e avisa sobre quem parou de responder. */
    private void monitorarEcho() {
        while (executando) {
            try {
                Thread.sleep(INTERVALO_ECHO_MS);
            } catch (InterruptedException interrompido) {
                return;
            }
            MensagemChat echo = new MensagemChat(MensagemChat.TIPO_ECHO, apelido, TEXTO_DO_ECHO);
            enviarParaTodos(echo, false);

            long agora = System.currentTimeMillis();
            for (PeerRemoto peer : peersAtivosPorApelido.values()) {
                long ultimaResposta = ultimoEchoPorEndereco.getOrDefault(peer.getChaveEndereco(), 0L);
                boolean semResposta = agora - ultimaResposta > LIMITE_SEM_RESPOSTA_ECHO_MS;
                if (semResposta && apelidosSemResposta.add(peer.getApelido())) {
                    imprimir("[aviso] " + peer.getApelido() + " não responde ao ECHO (pode estar inativo)");
                } else if (!semResposta && apelidosSemResposta.remove(peer.getApelido())) {
                    imprimir("[sistema] " + peer.getApelido() + " voltou a responder");
                }
            }
        }
    }

    /**
     * Envia uma mensagem por UDP diretamente a cada peer conhecido.
     *
     * @param mensagem      mensagem a enviar
     * @param avisarFalhas  se {@code true}, informa o usuário quando um envio falhar
     */
    private void enviarParaTodos(MensagemChat mensagem, boolean avisarFalhas) {
        byte[] dados = mensagem.codificar();
        for (PeerRemoto peer : peersAtivosPorApelido.values()) {
            try {
                socketUdp.send(new DatagramPacket(dados, dados.length, peer.getEndereco(), peer.getPortaUdp()));
            } catch (IOException erro) {
                if (avisarFalhas) {
                    imprimir("[aviso] falha ao enviar para " + peer.getApelido() + ": " + erro.getMessage());
                }
            }
        }
    }

    /** Laço de leitura do teclado; termina com /sair ou fim da entrada. */
    private void executarConsole() throws IOException {
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String linha;
        while ((linha = teclado.readLine()) != null) {
            linha = linha.trim();
            if (linha.isEmpty()) {
                continue;
            }
            if (!processarEntradaDoUsuario(linha)) {
                return;
            }
        }
    }

    /**
     * Interpreta uma linha digitada: comando (começa com "/") ou mensagem normal.
     *
     * @param linha texto digitado pelo usuário
     * @return {@code false} se o usuário pediu para sair; {@code true} caso contrário
     */
    private boolean processarEntradaDoUsuario(String linha) {
        if (!linha.startsWith("/")) {
            enviarTexto(MensagemChat.TIPO_NORMAL, RegistroEmojis.substituirCodigos(linha));
            return true;
        }
        String[] partes = linha.split("\\s+", 2);
        String comando = partes[0].toLowerCase();
        String argumento = (partes.length > 1) ? partes[1].trim() : "";

        switch (comando) {
            case "/sair":
                return false;
            case "/lista":
                imprimirPeers();
                break;
            case "/ativos":
                imprimirStatusDeAtividade();
                break;
            case "/emojis":
                imprimir("[sistema] emojis: " + RegistroEmojis.listarNomes()
                        + " (use /emoji <nome> ou :nome: dentro do texto)");
                break;
            case "/emoji":
                String icone = RegistroEmojis.buscarIcone(argumento);
                if (icone == null) {
                    imprimir("[sistema] emoji desconhecido. Use /emojis para ver a lista.");
                } else {
                    enviarTexto(MensagemChat.TIPO_EMOJI, icone);
                }
                break;
            case "/url":
                if (urlValida(argumento)) {
                    enviarTexto(MensagemChat.TIPO_URL, argumento);
                } else {
                    imprimir("[sistema] URL inválida. Exemplo: /url https://www.utfpr.edu.br");
                }
                break;
            case "/ajuda":
                imprimirAjuda();
                break;
            default:
                imprimir("[sistema] comando desconhecido. Digite /ajuda.");
                break;
        }
        return true;
    }

    /**
     * Envia um texto a todos os peers e o exibe localmente como "[você]".
     *
     * @param tipo  tipo da mensagem (normal, emoji ou URL)
     * @param texto conteúdo; é truncado em 255 bytes se for maior
     */
    private void enviarTexto(int tipo, String texto) {
        String textoAjustado = MensagemChat.truncarParaBytes(texto, MensagemChat.TAMANHO_MAXIMO_MENSAGEM_BYTES);
        if (!textoAjustado.equals(texto)) {
            imprimir("[aviso] mensagem truncada para 255 bytes (limite do protocolo)");
        }
        if (peersAtivosPorApelido.isEmpty()) {
            imprimir("[sistema] nenhum outro participante ativo no momento");
        }
        enviarParaTodos(new MensagemChat(tipo, apelido, textoAjustado), true);
        imprimir("[você] " + textoAjustado);
    }

    /**
     * Verifica se um texto é uma URL http ou https com host.
     *
     * @param texto texto a validar
     * @return {@code true} se for uma URL aceitável
     */
    private static boolean urlValida(String texto) {
        try {
            URI uri = new URI(texto);
            String esquema = uri.getScheme();
            return uri.getHost() != null && esquema != null
                    && (esquema.equalsIgnoreCase("http") || esquema.equalsIgnoreCase("https"));
        } catch (URISyntaxException erro) {
            return false;
        }
    }

    /** Mostra os participantes conhecidos. */
    private void imprimirPeers() {
        if (peersAtivosPorApelido.isEmpty()) {
            imprimir("[sistema] ninguém mais está no chat");
            return;
        }
        imprimir("[sistema] participantes ativos:");
        for (PeerRemoto peer : peersAtivosPorApelido.values()) {
            imprimir("   - " + peer);
        }
    }

    /** Mostra há quanto tempo cada peer respondeu a um ECHO. */
    private void imprimirStatusDeAtividade() {
        long agora = System.currentTimeMillis();
        for (PeerRemoto peer : peersAtivosPorApelido.values()) {
            long ultimaResposta = ultimoEchoPorEndereco.getOrDefault(peer.getChaveEndereco(), 0L);
            long segundos = (agora - ultimaResposta) / 1000;
            String situacao = apelidosSemResposta.contains(peer.getApelido()) ? "SEM RESPOSTA" : "ativo";
            imprimir("   - " + peer.getApelido() + ": " + situacao + " (último ECHO há " + segundos + " s)");
        }
    }

    /** Mostra os comandos disponíveis. */
    private void imprimirAjuda() {
        imprimir("[ajuda] texto livre = mensagem normal (aceita :feliz: etc.)");
        imprimir("[ajuda] /emoji <nome> | /emojis | /url <endereço> | /lista | /ativos | /sair");
    }

    /** Encerra threads, avisa o servidor (SAIR) e fecha os sockets. */
    private void encerrar() {
        executando = false;
        try {
            if (escritorServidor != null) {
                escritorServidor.write("SAIR\n");
                escritorServidor.flush();
            }
        } catch (IOException ignorado) {
            // O servidor remove o cliente quando a conexão cai de qualquer forma.
        }
        try {
            if (socketServidor != null) {
                socketServidor.close();
            }
        } catch (IOException ignorado) {
            // Encerrando.
        }
        if (socketUdp != null) {
            socketUdp.close();
        }
    }

    /**
     * Inicia uma thread daemon com nome.
     *
     * @param nome    nome da thread
     * @param tarefa  código a executar
     */
    private static void iniciarThread(String nome, Runnable tarefa) {
        Thread thread = new Thread(tarefa, nome);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Imprime uma linha na saída (sincronizado para não misturar linhas entre threads).
     *
     * @param texto linha a imprimir
     */
    private synchronized void imprimir(String texto) {
        saida.println(texto);
    }

    /**
     * Ponto de entrada: {@code java chat.ChatPeer <apelido> <portaUdp> [hostServidor] [portaServidor]}.
     *
     * @param argumentos apelido, porta UDP local, host do servidor (padrão localhost) e
     *                   porta do servidor (padrão 5000)
     */
    public static void main(String[] argumentos) {
        if (argumentos.length < 2) {
            System.err.println("Uso: java chat.ChatPeer <apelido> <portaUdp> [hostServidor] [portaServidor]");
            System.exit(1);
        }
        String host = (argumentos.length > 2) ? argumentos[2] : "localhost";
        int portaDoServidor = (argumentos.length > 3)
                ? Integer.parseInt(argumentos[3]) : ServidorListaAtivos.PORTA_PADRAO;
        try {
            new ChatPeer(argumentos[0], Integer.parseInt(argumentos[1]), host, portaDoServidor).iniciar();
        } catch (IOException | IllegalArgumentException erro) {
            System.err.println("Erro: " + erro.getMessage());
            System.exit(1);
        }
    }
}
