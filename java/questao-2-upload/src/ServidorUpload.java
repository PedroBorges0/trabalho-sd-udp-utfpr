/*
 * Arquivo....: ServidorUpload.java
 * Descrição..: Servidor UDP de upload de arquivos (Questão 2). Recebe o arquivo em blocos
 *              de 1024 bytes, confirma cada pacote com ACK (parar-e-esperar, pois o UDP não
 *              garante entrega), confere ao final o checksum SHA-1 e só então grava o arquivo
 *              definitivo na pasta de destino.
 *
 *              Opcionais implementados:
 *              - 2.a: log com horário de início e término, nome, tamanho e origem;
 *              - 2.d: transferências simultâneas (cada uma é uma "sessão" identificada por
 *                     origem + idTransferencia, com seu próprio arquivo temporário e SHA-1).
 *
 *              Segurança básica: o nome recebido é sanitizado (sem diretórios), o arquivo é
 *              gravado primeiro como .part e nunca sobrescreve um arquivo existente
 *              (acrescenta _1, _2, ... ao nome). Sessões inativas por 30 s são descartadas.
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package upload;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Servidor UDP que recebe arquivos e confere sua integridade com SHA-1.
 */
public class ServidorUpload {

    /** Porta UDP padrão do servidor de upload. */
    public static final int PORTA_PADRAO = 6000;
    /** Pasta padrão onde os arquivos recebidos são armazenados. */
    public static final String PASTA_PADRAO = "uploads_recebidos";
    /** Arquivo de log padrão. */
    public static final String ARQUIVO_LOG_PADRAO = "servidor_upload.log";

    private static final long INATIVIDADE_MAXIMA_MS = 30_000;
    private static final long INTERVALO_LIMPEZA_MS = 5_000;
    private static final int TAMANHO_BUFFER_SOCKET_BYTES = 4 * 1024 * 1024;
    private static final DateTimeFormatter FORMATO_HORARIO =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final int portaSolicitada;
    private final Path pastaDestino;
    private final Path arquivoLog;
    /** Sessões em andamento (ou recém-concluídas), por "origem/idTransferencia". */
    private final Map<String, SessaoRecepcao> sessoes = new ConcurrentHashMap<>();
    private final Object travaLog = new Object();

    private DatagramSocket socketUdp;
    private ScheduledExecutorService agendadorLimpeza;
    private volatile boolean executando;

    /**
     * @param portaUdp     porta UDP onde escutar (0 escolhe uma porta livre qualquer)
     * @param pastaDestino pasta onde os arquivos recebidos serão gravados (criada se não existir)
     * @param arquivoLog   arquivo de log (criado se não existir)
     */
    public ServidorUpload(int portaUdp, Path pastaDestino, Path arquivoLog) {
        this.portaSolicitada = portaUdp;
        this.pastaDestino = pastaDestino;
        this.arquivoLog = arquivoLog;
    }

    /**
     * Abre o socket UDP e inicia a thread de recepção e a limpeza de sessões inativas.
     * Retorna assim que o socket estiver aberto.
     *
     * @throws IOException se a pasta não puder ser criada ou a porta não puder ser aberta
     */
    public void iniciar() throws IOException {
        Files.createDirectories(pastaDestino);
        socketUdp = new DatagramSocket(portaSolicitada);
        socketUdp.setReceiveBufferSize(TAMANHO_BUFFER_SOCKET_BYTES);
        executando = true;

        Thread threadRecepcao = new Thread(this::laçoDeRecepcao, "recepcao-upload");
        threadRecepcao.setDaemon(true);
        threadRecepcao.start();

        agendadorLimpeza = Executors.newSingleThreadScheduledExecutor(tarefa -> {
            Thread thread = new Thread(tarefa, "limpeza-sessoes");
            thread.setDaemon(true);
            return thread;
        });
        agendadorLimpeza.scheduleWithFixedDelay(this::descartarSessoesInativas,
                INTERVALO_LIMPEZA_MS, INTERVALO_LIMPEZA_MS, TimeUnit.MILLISECONDS);

        registrarLog("SERVIDOR escutando na porta UDP " + getPortaEscutando()
                + ", pasta de destino: " + pastaDestino.toAbsolutePath());
    }

    /** Encerra o servidor, descartando as transferências incompletas. */
    public void parar() {
        executando = false;
        if (socketUdp != null) {
            socketUdp.close();
        }
        if (agendadorLimpeza != null) {
            agendadorLimpeza.shutdownNow();
        }
        for (SessaoRecepcao sessao : sessoes.values()) {
            synchronized (sessao) {
                if (!sessao.finalizada) {
                    sessao.abortar();
                }
            }
        }
        sessoes.clear();
    }

    /** @return porta UDP efetivamente aberta (útil quando se pede a porta 0) */
    public int getPortaEscutando() {
        return socketUdp.getLocalPort();
    }

    /** Laço que recebe datagramas e entrega cada pacote válido ao tratamento adequado. */
    private void laçoDeRecepcao() {
        byte[] buffer = new byte[ProtocoloUpload.TAMANHO_MAXIMO_DATAGRAMA_BYTES + 64];
        while (executando) {
            DatagramPacket datagrama = new DatagramPacket(buffer, buffer.length);
            try {
                socketUdp.receive(datagrama);
            } catch (IOException erro) {
                if (!executando) {
                    return;
                }
                registrarLog("ERRO ao receber datagrama: " + erro.getMessage());
                continue;
            }
            try {
                PacoteUpload pacote = PacoteUpload.decodificar(datagrama.getData(), datagrama.getLength());
                tratarPacote(pacote, datagrama.getSocketAddress());
            } catch (IllegalArgumentException pacoteInvalido) {
                // Datagrama que não segue o protocolo: ignorado.
            } catch (RuntimeException erroInesperado) {
                registrarLog("ERRO inesperado ao tratar pacote: " + erroInesperado);
            }
        }
    }

    /**
     * Encaminha um pacote ao tratamento do seu tipo.
     *
     * @param pacote pacote recebido
     * @param origem endereço de quem enviou (para onde as respostas vão)
     */
    private void tratarPacote(PacoteUpload pacote, SocketAddress origem) {
        String chave = formatarEndereco(origem) + "/" + pacote.getIdTransferencia();
        switch (pacote.getTipo()) {
            case ProtocoloUpload.TIPO_INICIO:
                tratarInicio(pacote, origem, chave);
                break;
            case ProtocoloUpload.TIPO_DADOS:
                tratarDados(pacote, origem, chave);
                break;
            case ProtocoloUpload.TIPO_FIM:
                tratarFim(pacote, origem, chave);
                break;
            default:
                break; // ACK e RESULTADO não são esperados no servidor
        }
    }

    /**
     * Trata INICIO: cria a sessão (ou apenas reconfirma, se for retransmissão) e envia ACK 0.
     *
     * @param pacote pacote INICIO
     * @param origem endereço do cliente
     * @param chave  chave da sessão
     */
    private void tratarInicio(PacoteUpload pacote, SocketAddress origem, String chave) {
        SessaoRecepcao existente = sessoes.get(chave);
        if (existente != null) {
            synchronized (existente) {
                existente.ultimaAtividadeMs = System.currentTimeMillis();
            }
            enviarPacote(origem, new PacoteUpload(ProtocoloUpload.TIPO_ACK, pacote.getIdTransferencia(), 0, null));
            return;
        }
        try {
            ProtocoloUpload.InformacaoArquivo informacao = ProtocoloUpload.lerCargaInicio(pacote.getCarga());
            String nomeSeguro = sanitizarNomeArquivo(informacao.getNome());
            int totalBlocos = ProtocoloUpload.calcularTotalBlocos(informacao.getTamanhoBytes());
            Path arquivoTemporario = Files.createTempFile(pastaDestino, "upload_", ".part");
            SessaoRecepcao sessao = new SessaoRecepcao(origem, nomeSeguro, informacao.getTamanhoBytes(),
                    totalBlocos, arquivoTemporario);
            sessoes.put(chave, sessao);
            registrarLog("INICIO horario=" + formatarHorario(sessao.inicio) + " origem=" + formatarEndereco(origem)
                    + " arquivo=" + nomeSeguro + " tamanho=" + informacao.getTamanhoBytes());
            enviarPacote(origem, new PacoteUpload(ProtocoloUpload.TIPO_ACK, pacote.getIdTransferencia(), 0, null));
        } catch (IllegalArgumentException | IOException erro) {
            enviarResultado(origem, pacote.getIdTransferencia(), 0, ProtocoloUpload.STATUS_ERRO,
                    "INICIO recusado: " + erro.getMessage());
        }
    }

    /**
     * Trata DADOS: grava o bloco se for o esperado e confirma com ACK. Duplicatas são
     * apenas reconfirmadas; blocos adiantados são ignorados (o cliente retransmite).
     *
     * @param pacote pacote DADOS
     * @param origem endereço do cliente
     * @param chave  chave da sessão
     */
    private void tratarDados(PacoteUpload pacote, SocketAddress origem, String chave) {
        int id = pacote.getIdTransferencia();
        SessaoRecepcao sessao = sessoes.get(chave);
        if (sessao == null) {
            enviarResultado(origem, id, pacote.getSequencia(), ProtocoloUpload.STATUS_ERRO,
                    "transferencia desconhecida: envie INICIO primeiro");
            return;
        }
        synchronized (sessao) {
            sessao.ultimaAtividadeMs = System.currentTimeMillis();
            if (sessao.finalizada) {
                reenviarResultado(origem, id, sessao);
                return;
            }
            int sequencia = pacote.getSequencia();
            if (sequencia < sessao.proximaSequenciaDados) {
                enviarPacote(origem, new PacoteUpload(ProtocoloUpload.TIPO_ACK, id, sequencia, null));
                return;
            }
            if (sequencia > sessao.proximaSequenciaDados) {
                return; // fora de ordem
            }
            byte[] carga = pacote.getCarga();
            boolean sequenciaValida = sequencia <= sessao.totalBlocos;
            boolean tamanhoValido = sequenciaValida
                    && carga.length == ProtocoloUpload.calcularTamanhoDoBloco(sessao.tamanhoArquivo, sequencia);
            if (!tamanhoValido) {
                finalizarComErro(origem, id, sequencia, sessao, "bloco com tamanho ou sequencia invalidos");
                return;
            }
            try {
                sessao.gravarBloco(carga);
            } catch (IOException erroDeDisco) {
                finalizarComErro(origem, id, sequencia, sessao, "falha ao gravar no disco");
                return;
            }
            enviarPacote(origem, new PacoteUpload(ProtocoloUpload.TIPO_ACK, id, sequencia, null));
        }
    }

    /**
     * Trata FIM: confere o SHA-1, grava (ou descarta) o arquivo, registra o log e envia RESULTADO.
     *
     * @param pacote pacote FIM (carga = SHA-1 de 20 bytes)
     * @param origem endereço do cliente
     * @param chave  chave da sessão
     */
    private void tratarFim(PacoteUpload pacote, SocketAddress origem, String chave) {
        int id = pacote.getIdTransferencia();
        SessaoRecepcao sessao = sessoes.get(chave);
        if (sessao == null) {
            enviarResultado(origem, id, pacote.getSequencia(), ProtocoloUpload.STATUS_ERRO,
                    "transferencia desconhecida: envie INICIO primeiro");
            return;
        }
        synchronized (sessao) {
            sessao.ultimaAtividadeMs = System.currentTimeMillis();
            if (sessao.finalizada) {
                reenviarResultado(origem, id, sessao);
                return;
            }
            int sequenciaFim = sessao.totalBlocos + 1;
            byte[] sha1Recebido = pacote.getCarga();
            boolean estadoValido = pacote.getSequencia() == sequenciaFim
                    && sessao.proximaSequenciaDados == sequenciaFim
                    && sha1Recebido.length == ProtocoloUpload.TAMANHO_SHA1_BYTES;
            if (!estadoValido) {
                finalizarComErro(origem, id, sequenciaFim, sessao, "FIM invalido ou blocos faltando");
                return;
            }
            sessao.concluir(sha1Recebido, pastaDestino);
            registrarFimNoLog(sessao, origem);
            reenviarResultado(origem, id, sessao);
        }
    }

    /**
     * Aborta a sessão por erro, registra no log e avisa o cliente com RESULTADO de erro.
     *
     * @param origem    endereço do cliente
     * @param id        identificador da transferência
     * @param sequencia sequência a ecoar no RESULTADO
     * @param sessao    sessão com problema (já sincronizada pelo chamador)
     * @param motivo    explicação curta
     */
    private void finalizarComErro(SocketAddress origem, int id, int sequencia, SessaoRecepcao sessao, String motivo) {
        sessao.abortar();
        sessao.status = ProtocoloUpload.STATUS_ERRO;
        sessao.mensagemResultado = motivo;
        registrarFimNoLog(sessao, origem);
        enviarResultado(origem, id, sequencia, sessao.status, motivo);
    }

    /**
     * Escreve a linha de log de término de uma transferência (opcional 2.a).
     *
     * @param sessao sessão finalizada
     * @param origem endereço do cliente
     */
    private void registrarFimNoLog(SessaoRecepcao sessao, SocketAddress origem) {
        sessao.fim = Instant.now();
        registrarLog("FIM inicio=" + formatarHorario(sessao.inicio) + " fim=" + formatarHorario(sessao.fim)
                + " origem=" + formatarEndereco(origem) + " arquivo=" + sessao.nomeArquivo
                + " tamanho=" + sessao.tamanhoArquivo + " recebido=" + sessao.bytesRecebidos
                + " status=" + nomeDoStatus(sessao.status)
                + (sessao.arquivoFinal != null ? " salvo_como=" + sessao.arquivoFinal.getFileName() : "")
                + " detalhe=\"" + sessao.mensagemResultado + "\"");
    }

    /**
     * Remove sessões sem atividade há mais de 30 s; as incompletas têm o temporário apagado.
     */
    private void descartarSessoesInativas() {
        long agora = System.currentTimeMillis();
        for (Map.Entry<String, SessaoRecepcao> entrada : sessoes.entrySet()) {
            SessaoRecepcao sessao = entrada.getValue();
            synchronized (sessao) {
                if (agora - sessao.ultimaAtividadeMs <= INATIVIDADE_MAXIMA_MS) {
                    continue;
                }
                if (!sessao.finalizada) {
                    sessao.abortar();
                    sessao.status = ProtocoloUpload.STATUS_ERRO;
                    sessao.mensagemResultado = "abortada por inatividade";
                    registrarFimNoLog(sessao, sessao.origem);
                }
                sessoes.remove(entrada.getKey());
            }
        }
    }

    /**
     * Envia um pacote ao cliente, registrando no log se o envio falhar.
     *
     * @param destino endereço do cliente
     * @param pacote  pacote a enviar
     */
    private void enviarPacote(SocketAddress destino, PacoteUpload pacote) {
        byte[] dados = pacote.codificar();
        try {
            socketUdp.send(new DatagramPacket(dados, dados.length, destino));
        } catch (IOException erro) {
            if (executando) {
                registrarLog("ERRO ao enviar para " + formatarEndereco(destino) + ": " + erro.getMessage());
            }
        }
    }

    /**
     * Envia um pacote RESULTADO.
     *
     * @param destino   endereço do cliente
     * @param id        identificador da transferência
     * @param sequencia sequência do pacote que originou o resultado
     * @param status    um dos valores {@code STATUS_*}
     * @param mensagem  explicação curta
     */
    private void enviarResultado(SocketAddress destino, int id, int sequencia, int status, String mensagem) {
        enviarPacote(destino, new PacoteUpload(ProtocoloUpload.TIPO_RESULTADO, id, sequencia,
                ProtocoloUpload.montarCargaResultado(status, mensagem)));
    }

    /**
     * Envia (ou reenvia) o RESULTADO guardado de uma sessão já finalizada.
     *
     * @param destino endereço do cliente
     * @param id      identificador da transferência
     * @param sessao  sessão finalizada
     */
    private void reenviarResultado(SocketAddress destino, int id, SessaoRecepcao sessao) {
        enviarResultado(destino, id, sessao.totalBlocos + 1, sessao.status, sessao.mensagemResultado);
    }

    /**
     * Remove diretórios e caracteres de controle de um nome de arquivo vindo da rede,
     * impedindo gravação fora da pasta de destino (ex.: "../../etc/passwd" vira "passwd").
     *
     * @param nomeRecebido nome enviado pelo cliente
     * @return nome seguro, apenas o último componente
     * @throws IllegalArgumentException se não sobrar um nome utilizável
     */
    public static String sanitizarNomeArquivo(String nomeRecebido) {
        String semControle = nomeRecebido.replaceAll("\\p{Cntrl}", "");
        int ultimoSeparador = Math.max(semControle.lastIndexOf('/'), semControle.lastIndexOf('\\'));
        String nome = semControle.substring(ultimoSeparador + 1).trim();
        if (nome.isEmpty() || nome.equals(".") || nome.equals("..")) {
            throw new IllegalArgumentException("nome de arquivo invalido");
        }
        return nome;
    }

    /**
     * Escolhe um caminho livre na pasta, acrescentando _1, _2, ... antes da extensão se preciso.
     *
     * @param pasta pasta de destino
     * @param nome  nome desejado (já sanitizado)
     * @param indice 0 para tentar o nome original, 1 em diante para os sufixos
     * @return caminho candidato (pode ainda ser disputado; o move trata a corrida)
     */
    private static Path montarCaminhoCandidato(Path pasta, String nome, int indice) {
        if (indice == 0) {
            return pasta.resolve(nome);
        }
        int pontoExtensao = nome.lastIndexOf('.');
        String base = (pontoExtensao > 0) ? nome.substring(0, pontoExtensao) : nome;
        String extensao = (pontoExtensao > 0) ? nome.substring(pontoExtensao) : "";
        return pasta.resolve(base + "_" + indice + extensao);
    }

    /**
     * Escreve uma linha no console e no arquivo de log, com horário.
     *
     * @param linha texto do evento
     */
    private void registrarLog(String linha) {
        String completa = "[" + FORMATO_HORARIO.format(Instant.now()) + "] " + linha;
        System.out.println(completa);
        synchronized (travaLog) {
            try {
                Path pai = arquivoLog.toAbsolutePath().getParent();
                if (pai != null) {
                    Files.createDirectories(pai);
                }
                Files.write(arquivoLog, (completa + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException erro) {
                System.err.println("Não foi possível escrever no log: " + erro.getMessage());
            }
        }
    }

    /**
     * Formata um instante para o log.
     *
     * @param instante instante a formatar
     * @return texto no formato yyyy-MM-dd HH:mm:ss.SSS
     */
    private static String formatarHorario(Instant instante) {
        return FORMATO_HORARIO.format(instante);
    }

    /**
     * Formata um endereço de socket como "ip:porta".
     *
     * @param endereco endereço de origem ou destino
     * @return texto "ip:porta"
     */
    private static String formatarEndereco(SocketAddress endereco) {
        InetSocketAddress inet = (InetSocketAddress) endereco;
        return inet.getAddress().getHostAddress() + ":" + inet.getPort();
    }

    /**
     * Converte um código de status em texto.
     *
     * @param status valor {@code STATUS_*}
     * @return nome legível
     */
    private static String nomeDoStatus(int status) {
        switch (status) {
            case ProtocoloUpload.STATUS_OK:
                return "OK";
            case ProtocoloUpload.STATUS_CHECKSUM_DIVERGENTE:
                return "CHECKSUM_DIVERGENTE";
            default:
                return "ERRO";
        }
    }

    /**
     * Ponto de entrada: {@code java upload.ServidorUpload [porta] [pastaDestino] [arquivoLog]}.
     *
     * @param argumentos porta UDP (padrão 6000), pasta de destino (padrão uploads_recebidos)
     *                   e arquivo de log (padrão servidor_upload.log)
     * @throws IOException se o servidor não puder ser iniciado
     */
    public static void main(String[] argumentos) throws IOException {
        int porta = (argumentos.length > 0) ? Integer.parseInt(argumentos[0]) : PORTA_PADRAO;
        Path pasta = Paths.get((argumentos.length > 1) ? argumentos[1] : PASTA_PADRAO);
        Path log = Paths.get((argumentos.length > 2) ? argumentos[2] : ARQUIVO_LOG_PADRAO);
        new ServidorUpload(porta, pasta, log).iniciar();
        // As threads do servidor são daemon: mantém a JVM viva até Ctrl+C.
        try {
            Thread.currentThread().join();
        } catch (InterruptedException interrompido) {
            Thread.currentThread().interrupt();
        }
    }

    /** Estado de uma transferência em andamento no servidor. Campos protegidos por synchronized(this). */
    private static final class SessaoRecepcao {
        final SocketAddress origem;
        final String nomeArquivo;
        final long tamanhoArquivo;
        final int totalBlocos;
        final Path arquivoTemporario;
        final Instant inicio = Instant.now();
        final MessageDigest sha1;
        OutputStream saida;

        int proximaSequenciaDados = 1;
        long bytesRecebidos;
        long ultimaAtividadeMs = System.currentTimeMillis();
        boolean finalizada;
        int status = ProtocoloUpload.STATUS_ERRO;
        String mensagemResultado = "";
        Path arquivoFinal;
        Instant fim;

        /**
         * @param origem            endereço do cliente
         * @param nomeArquivo       nome já sanitizado
         * @param tamanhoArquivo    tamanho anunciado
         * @param totalBlocos       quantidade de blocos esperada
         * @param arquivoTemporario arquivo .part onde os blocos são gravados
         * @throws IOException se o temporário não puder ser aberto
         */
        SessaoRecepcao(SocketAddress origem, String nomeArquivo, long tamanhoArquivo, int totalBlocos,
                       Path arquivoTemporario) throws IOException {
            this.origem = origem;
            this.nomeArquivo = nomeArquivo;
            this.tamanhoArquivo = tamanhoArquivo;
            this.totalBlocos = totalBlocos;
            this.arquivoTemporario = arquivoTemporario;
            try {
                this.sha1 = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-1 indisponível na JVM", e);
            }
            this.saida = new BufferedOutputStream(Files.newOutputStream(arquivoTemporario));
        }

        /**
         * Grava um bloco no temporário e o inclui no cálculo do SHA-1.
         *
         * @param bloco bytes do bloco
         * @throws IOException se a gravação falhar
         */
        void gravarBloco(byte[] bloco) throws IOException {
            saida.write(bloco);
            sha1.update(bloco);
            bytesRecebidos += bloco.length;
            proximaSequenciaDados++;
        }

        /**
         * Fecha o temporário, compara o SHA-1 e move o arquivo para o destino final se estiver íntegro.
         *
         * @param sha1Recebido checksum enviado pelo cliente (20 bytes)
         * @param pasta        pasta de destino
         */
        void concluir(byte[] sha1Recebido, Path pasta) {
            byte[] sha1Calculado = sha1.digest();
            try {
                saida.close();
            } catch (IOException ignorado) {
                // Será detectado na conferência abaixo.
            }
            boolean integro = bytesRecebidos == tamanhoArquivo && Arrays.equals(sha1Calculado, sha1Recebido);
            try {
                if (integro) {
                    arquivoFinal = moverParaDestinoFinal(pasta);
                    status = ProtocoloUpload.STATUS_OK;
                    mensagemResultado = "arquivo salvo como " + arquivoFinal.getFileName()
                            + " sha1=" + paraHexadecimal(sha1Calculado);
                } else {
                    Files.deleteIfExists(arquivoTemporario);
                    status = ProtocoloUpload.STATUS_CHECKSUM_DIVERGENTE;
                    mensagemResultado = "checksum SHA-1 divergente (calculado "
                            + paraHexadecimal(sha1Calculado) + "); arquivo descartado";
                }
            } catch (IOException erro) {
                status = ProtocoloUpload.STATUS_ERRO;
                mensagemResultado = "falha ao salvar o arquivo: " + erro.getMessage();
            }
            finalizada = true;
        }

        /** Fecha e apaga o temporário e marca a sessão como finalizada (sem arquivo salvo). */
        void abortar() {
            try {
                saida.close();
                Files.deleteIfExists(arquivoTemporario);
            } catch (IOException ignorado) {
                // Melhor esforço.
            }
            finalizada = true;
        }

        /**
         * Move o temporário para um nome livre na pasta final, sem sobrescrever arquivos.
         *
         * @param pasta pasta de destino
         * @return caminho final do arquivo
         * @throws IOException se não for possível mover
         */
        private Path moverParaDestinoFinal(Path pasta) throws IOException {
            for (int indice = 0; ; indice++) {
                Path candidato = montarCaminhoCandidato(pasta, nomeArquivo, indice);
                try {
                    Files.move(arquivoTemporario, candidato);
                    return candidato;
                } catch (FileAlreadyExistsException jaExiste) {
                    // Tenta o próximo sufixo.
                }
            }
        }

        /**
         * Converte bytes em texto hexadecimal.
         *
         * @param dados bytes a converter
         * @return texto hexadecimal em minúsculas
         */
        private static String paraHexadecimal(byte[] dados) {
            StringBuilder texto = new StringBuilder();
            for (byte b : dados) {
                texto.append(String.format("%02x", b));
            }
            return texto.toString();
        }
    }
}
