/*
 * Arquivo....: ServidorListaAtivos.java
 * Descrição..: Servidor TCP que mantém a lista de pessoas ativas no chat P2P
 *              (opcionais 1.a, 1.b e 1.c da Questão 1).
 *
 *              - 1.a: o cliente se registra com "ENTRAR <apelido> <portaUdp>"; o servidor
 *                     guarda apelido + endereço IP (visto na conexão TCP) + porta UDP.
 *              - 1.b: ao fechar a conexão TCP (ou enviar "SAIR"), o cliente é removido.
 *              - 1.c: o servidor ENVIA uma notificação (mensagem "LISTA") a todos os
 *                     clientes sempre que a lista muda (entrada ou saída).
 *
 *              Protocolo de texto (uma linha por comando, UTF-8, terminada em \n):
 *                Cliente -> Servidor:  ENTRAR <apelido> <portaUdp> | LISTAR | SAIR
 *                Servidor -> Cliente:  OK | ERRO <motivo> | LISTA <n> seguido de n linhas
 *                                      "<apelido> <ip> <portaUdp>"
 *              Detalhes completos em docs/PROTOCOLO_CHAT.txt.
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package chat;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Servidor TCP da lista de participantes ativos.
 */
public class ServidorListaAtivos {

    /** Porta TCP padrão do servidor. */
    public static final int PORTA_PADRAO = 5000;

    private static final String COMANDO_ENTRAR = "ENTRAR";
    private static final String COMANDO_LISTAR = "LISTAR";
    private static final String COMANDO_SAIR = "SAIR";

    private final int portaSolicitada;
    /** Sessões ativas por apelido, em ordem de entrada. Acesso protegido por synchronized. */
    private final Map<String, SessaoCliente> sessoesPorApelido = new LinkedHashMap<>();

    private ServerSocket socketServidor;
    private ExecutorService executorConexoes;
    private volatile boolean executando;

    /**
     * @param portaTcp porta TCP onde escutar (0 escolhe uma porta livre qualquer)
     */
    public ServidorListaAtivos(int portaTcp) {
        this.portaSolicitada = portaTcp;
    }

    /**
     * Abre a porta TCP e começa a aceitar clientes em uma thread própria.
     * Retorna assim que a porta estiver aberta.
     *
     * @throws IOException se não for possível abrir a porta
     */
    public void iniciar() throws IOException {
        socketServidor = new ServerSocket(portaSolicitada);
        executando = true;
        executorConexoes = Executors.newCachedThreadPool(tarefa -> {
            Thread thread = new Thread(tarefa, "cliente-lista-ativos");
            thread.setDaemon(true);
            return thread;
        });
        Thread aceitador = new Thread(this::aceitarConexoes, "aceitador-lista-ativos");
        aceitador.start();
        registrarEvento("escutando na porta TCP " + getPortaEscutando());
    }

    /**
     * Encerra o servidor e fecha todas as conexões de clientes.
     */
    public void parar() {
        executando = false;
        try {
            if (socketServidor != null) {
                socketServidor.close();
            }
        } catch (IOException ignorado) {
            // Encerrando de qualquer forma.
        }
        List<SessaoCliente> sessoes;
        synchronized (sessoesPorApelido) {
            sessoes = new ArrayList<>(sessoesPorApelido.values());
        }
        for (SessaoCliente sessao : sessoes) {
            fecharSilenciosamente(sessao.socket);
        }
        if (executorConexoes != null) {
            executorConexoes.shutdownNow();
        }
    }

    /** @return porta TCP efetivamente aberta (útil quando se pede a porta 0) */
    public int getPortaEscutando() {
        return socketServidor.getLocalPort();
    }

    /** Laço que aceita novas conexões TCP e entrega cada uma a uma thread do pool. */
    private void aceitarConexoes() {
        while (executando) {
            try {
                Socket conexao = socketServidor.accept();
                executorConexoes.submit(() -> atenderCliente(conexao));
            } catch (SocketException socketFechado) {
                break; // parar() foi chamado
            } catch (IOException erro) {
                if (executando) {
                    registrarEvento("erro ao aceitar conexão: " + erro.getMessage());
                }
            }
        }
    }

    /**
     * Atende um cliente do início ao fim: registro, comandos e remoção ao desconectar (1.b).
     *
     * @param conexao socket TCP do cliente
     */
    private void atenderCliente(Socket conexao) {
        SessaoCliente sessao = null;
        try {
            BufferedReader leitor = new BufferedReader(
                    new InputStreamReader(conexao.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter escritor = new BufferedWriter(
                    new OutputStreamWriter(conexao.getOutputStream(), StandardCharsets.UTF_8));

            sessao = tentarRegistrar(leitor.readLine(), conexao, escritor);
            if (sessao == null) {
                return; // registro recusado: o ERRO já foi enviado
            }
            notificarTodos();

            String linha;
            while ((linha = leitor.readLine()) != null) {
                String comando = linha.trim().toUpperCase();
                if (comando.equals(COMANDO_LISTAR)) {
                    sessao.enviar(montarMensagemLista());
                } else if (comando.equals(COMANDO_SAIR)) {
                    break;
                } else {
                    sessao.enviar("ERRO comando desconhecido\n");
                }
            }
        } catch (IOException conexaoEncerrada) {
            // Cliente caiu: tratado no finally como uma saída normal.
        } finally {
            if (sessao != null) {
                removerSessao(sessao);
                notificarTodos();
            }
            fecharSilenciosamente(conexao);
        }
    }

    /**
     * Valida o comando ENTRAR e, se estiver correto, registra o cliente na lista.
     *
     * @param linhaEntrar primeira linha enviada pelo cliente
     * @param conexao     socket do cliente (fornece o endereço IP)
     * @param escritor    canal de resposta ao cliente
     * @return a sessão criada, ou {@code null} se o registro foi recusado
     * @throws IOException se houver falha ao responder
     */
    private SessaoCliente tentarRegistrar(String linhaEntrar, Socket conexao, BufferedWriter escritor)
            throws IOException {
        SessaoCliente sessaoProvisoria = new SessaoCliente(null, null, 0, conexao, escritor);
        if (linhaEntrar == null) {
            return null;
        }
        String[] partes = linhaEntrar.trim().split("\\s+");
        if (partes.length != 3 || !partes[0].equalsIgnoreCase(COMANDO_ENTRAR)) {
            sessaoProvisoria.enviar("ERRO use: ENTRAR <apelido> <portaUdp>\n");
            return null;
        }
        String apelido = partes[1];
        int tamanhoApelido = apelido.getBytes(StandardCharsets.UTF_8).length;
        if (tamanhoApelido < MensagemChat.TAMANHO_MINIMO_APELIDO_BYTES
                || tamanhoApelido > MensagemChat.TAMANHO_MAXIMO_APELIDO_BYTES) {
            sessaoProvisoria.enviar("ERRO apelido deve ter de 1 a 64 bytes\n");
            return null;
        }
        int portaUdp;
        try {
            portaUdp = Integer.parseInt(partes[2]);
        } catch (NumberFormatException e) {
            sessaoProvisoria.enviar("ERRO porta UDP invalida\n");
            return null;
        }
        if (portaUdp < 1 || portaUdp > 65535) {
            sessaoProvisoria.enviar("ERRO porta UDP fora do intervalo 1-65535\n");
            return null;
        }

        InetAddress enderecoCliente = conexao.getInetAddress();
        SessaoCliente sessao = new SessaoCliente(apelido, enderecoCliente, portaUdp, conexao, escritor);
        synchronized (sessoesPorApelido) {
            if (sessoesPorApelido.containsKey(apelido)) {
                sessao.enviar("ERRO apelido ja esta em uso\n");
                return null;
            }
            sessao.enviar("OK\n");
            sessoesPorApelido.put(apelido, sessao);
        }
        registrarEvento("entrou: " + apelido + " " + enderecoCliente.getHostAddress() + ":" + portaUdp);
        return sessao;
    }

    /**
     * Remove um cliente da lista (opcional 1.b).
     *
     * @param sessao sessão do cliente que saiu
     */
    private void removerSessao(SessaoCliente sessao) {
        boolean removida;
        synchronized (sessoesPorApelido) {
            removida = sessoesPorApelido.remove(sessao.apelido, sessao);
        }
        if (removida) {
            registrarEvento("saiu: " + sessao.apelido);
        }
    }

    /**
     * Envia a lista atualizada a todos os clientes conectados (opcional 1.c, notificação
     * disparada pelo servidor a cada mudança de estado).
     */
    private void notificarTodos() {
        List<SessaoCliente> destinatarios;
        String mensagemLista;
        synchronized (sessoesPorApelido) {
            destinatarios = new ArrayList<>(sessoesPorApelido.values());
            mensagemLista = montarMensagemLista();
        }
        for (SessaoCliente destinatario : destinatarios) {
            try {
                destinatario.enviar(mensagemLista);
            } catch (IOException conexaoComFalha) {
                // A thread desse cliente perceberá a queda e fará a remoção.
            }
        }
    }

    /**
     * Monta o texto "LISTA n" + n linhas "apelido ip porta" com o estado atual.
     *
     * @return mensagem de lista pronta para envio
     */
    private String montarMensagemLista() {
        StringBuilder texto = new StringBuilder();
        synchronized (sessoesPorApelido) {
            texto.append("LISTA ").append(sessoesPorApelido.size()).append('\n');
            for (SessaoCliente sessao : sessoesPorApelido.values()) {
                texto.append(sessao.apelido).append(' ')
                        .append(sessao.endereco.getHostAddress()).append(' ')
                        .append(sessao.portaUdp).append('\n');
            }
        }
        return texto.toString();
    }

    /**
     * Fecha um socket ignorando erros.
     *
     * @param socket socket a fechar
     */
    private static void fecharSilenciosamente(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignorado) {
            // Nada a fazer.
        }
    }

    /**
     * Escreve um evento do servidor na saída padrão.
     *
     * @param descricao texto do evento
     */
    private static void registrarEvento(String descricao) {
        System.out.println("[servidor-lista] " + descricao);
    }

    /**
     * Ponto de entrada: {@code java chat.ServidorListaAtivos [portaTcp]}.
     *
     * @param argumentos opcionalmente a porta TCP (padrão 5000)
     * @throws IOException se a porta não puder ser aberta
     */
    public static void main(String[] argumentos) throws IOException {
        int porta = (argumentos.length > 0) ? Integer.parseInt(argumentos[0]) : PORTA_PADRAO;
        new ServidorListaAtivos(porta).iniciar();
    }

    /** Dados de um cliente conectado ao servidor. */
    private static final class SessaoCliente {
        private final String apelido;
        private final InetAddress endereco;
        private final int portaUdp;
        private final Socket socket;
        private final BufferedWriter escritor;

        SessaoCliente(String apelido, InetAddress endereco, int portaUdp, Socket socket, BufferedWriter escritor) {
            this.apelido = apelido;
            this.endereco = endereco;
            this.portaUdp = portaUdp;
            this.socket = socket;
            this.escritor = escritor;
        }

        /**
         * Envia texto ao cliente (sincronizado, pois várias threads podem escrever).
         *
         * @param texto texto já com as quebras de linha
         * @throws IOException se a conexão estiver quebrada
         */
        synchronized void enviar(String texto) throws IOException {
            escritor.write(texto);
            escritor.flush();
        }
    }
}
