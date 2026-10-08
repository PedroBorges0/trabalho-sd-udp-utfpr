/*
 * Arquivo....: ClienteUpload.java
 * Descrição..: Núcleo do cliente de upload via UDP (Questão 2). Envia um arquivo em blocos
 *              de 1024 bytes ao ServidorUpload usando o protocolo da especificação:
 *              INICIO (nome + tamanho) -> DADOS 1..N -> FIM (SHA-1) -> RESULTADO.
 *              Como o UDP pode perder pacotes, cada pacote é retransmitido até receber o
 *              ACK correspondente (parar-e-esperar, com limite de tentativas).
 *
 *              Fornece callback de progresso (usado pela barra de estado, opcional 2.c) e
 *              pode ser chamado de várias threads ao mesmo tempo (opcional 2.d).
 *              Possui ainda ganchos de teste: perda simulada de pacotes e checksum corrompido.
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package upload;

import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Cliente de upload de arquivos via UDP.
 */
public class ClienteUpload {

    /** Tempo padrão de espera por uma resposta antes de retransmitir, em milissegundos. */
    public static final int TIMEOUT_PADRAO_RESPOSTA_MS = 300;
    /** Quantidade máxima de envios de um mesmo pacote antes de desistir. */
    public static final int MAXIMO_TENTATIVAS_POR_PACOTE = 40;

    private volatile int timeoutRespostaMs = TIMEOUT_PADRAO_RESPOSTA_MS;
    private volatile double probabilidadePerdaSimulada = 0.0;
    private volatile boolean corromperChecksumParaTeste = false;

    /** Recebe o andamento do envio (usado pela interface gráfica e pela linha de comando). */
    public interface OuvinteProgresso {
        /**
         * Chamado após cada bloco confirmado pelo servidor.
         *
         * @param bytesEnviados bytes do arquivo já confirmados
         * @param bytesTotais   tamanho total do arquivo
         */
        void aoProgredir(long bytesEnviados, long bytesTotais);
    }

    /** Resultado final de um upload, conforme informado pelo servidor. */
    public static final class ResultadoUpload {
        private final int status;
        private final String mensagem;

        /**
         * @param status   um dos valores {@code ProtocoloUpload.STATUS_*}
         * @param mensagem texto explicativo enviado pelo servidor
         */
        public ResultadoUpload(int status, String mensagem) {
            this.status = status;
            this.mensagem = mensagem;
        }

        /** @return {@code true} se o servidor confirmou que o arquivo foi salvo íntegro */
        public boolean isSucesso() {
            return status == ProtocoloUpload.STATUS_OK;
        }

        /** @return código de status ({@code ProtocoloUpload.STATUS_*}) */
        public int getStatus() {
            return status;
        }

        /** @return mensagem enviada pelo servidor */
        public String getMensagem() {
            return mensagem;
        }
    }

    /**
     * Envia um arquivo ao servidor e aguarda a confirmação de integridade.
     *
     * @param arquivo       caminho do arquivo local (precisa existir e ser um arquivo comum)
     * @param hostServidor  nome ou IP do servidor de upload
     * @param portaServidor porta UDP do servidor
     * @param ouvinte       callback de progresso (pode ser {@code null})
     * @return o resultado informado pelo servidor (sucesso, checksum divergente ou erro)
     * @throws IOException se o arquivo não puder ser lido, o servidor não responder após as
     *                     retransmissões, ou o servidor abortar a transferência
     */
    public ResultadoUpload enviarArquivo(Path arquivo, String hostServidor, int portaServidor,
                                         OuvinteProgresso ouvinte) throws IOException {
        if (!Files.isRegularFile(arquivo)) {
            throw new FileNotFoundException("Arquivo não encontrado: " + arquivo);
        }
        long tamanhoArquivo = Files.size(arquivo);
        int totalBlocos = ProtocoloUpload.calcularTotalBlocos(tamanhoArquivo);
        InetAddress enderecoServidor = InetAddress.getByName(hostServidor);
        int idTransferencia = ThreadLocalRandom.current().nextInt(1, Integer.MAX_VALUE);
        MessageDigest sha1 = criarSha1();

        try (DatagramSocket socket = new DatagramSocket();
             InputStream entrada = new BufferedInputStream(Files.newInputStream(arquivo))) {

            notificar(ouvinte, 0, tamanhoArquivo);

            // 1) INICIO (sequência 0): nome e tamanho.
            String nomeArquivo = arquivo.getFileName().toString();
            enviarEEsperar(socket, enderecoServidor, portaServidor,
                    new PacoteUpload(ProtocoloUpload.TIPO_INICIO, idTransferencia, 0,
                            ProtocoloUpload.montarCargaInicio(nomeArquivo, tamanhoArquivo)),
                    false);

            // 2) DADOS (sequências 1..N): blocos de 1024 bytes, o último com o restante.
            byte[] bloco = new byte[ProtocoloUpload.TAMANHO_BLOCO_DADOS_BYTES];
            long bytesConfirmados = 0;
            for (int sequencia = 1; sequencia <= totalBlocos; sequencia++) {
                int esperado = ProtocoloUpload.calcularTamanhoDoBloco(tamanhoArquivo, sequencia);
                int lidos = entrada.readNBytes(bloco, 0, esperado);
                if (lidos != esperado) {
                    throw new IOException("O arquivo mudou de tamanho durante o envio");
                }
                sha1.update(bloco, 0, lidos);
                enviarEEsperar(socket, enderecoServidor, portaServidor,
                        new PacoteUpload(ProtocoloUpload.TIPO_DADOS, idTransferencia, sequencia,
                                Arrays.copyOf(bloco, lidos)),
                        false);
                bytesConfirmados += lidos;
                notificar(ouvinte, bytesConfirmados, tamanhoArquivo);
            }

            // 3) FIM (sequência N+1): checksum SHA-1; a resposta é o RESULTADO.
            byte[] checksum = sha1.digest();
            if (corromperChecksumParaTeste) {
                checksum[0] ^= (byte) 0xFF;
            }
            PacoteUpload resultado = enviarEEsperar(socket, enderecoServidor, portaServidor,
                    new PacoteUpload(ProtocoloUpload.TIPO_FIM, idTransferencia, totalBlocos + 1, checksum),
                    true);
            byte[] carga = resultado.getCarga();
            return new ResultadoUpload(ProtocoloUpload.lerStatusResultado(carga),
                    ProtocoloUpload.lerMensagemResultado(carga));
        }
    }

    /**
     * Envia um pacote e espera a resposta certa, retransmitindo em caso de timeout.
     *
     * @param socket          socket UDP do cliente
     * @param destino         endereço do servidor
     * @param porta           porta do servidor
     * @param pacote          pacote a enviar
     * @param esperaResultado {@code true} para aguardar um RESULTADO (pacote FIM);
     *                        {@code false} para aguardar o ACK da mesma sequência
     * @return a resposta aceita (ACK ou RESULTADO)
     * @throws IOException se o servidor não responder após todas as tentativas, ou se enviar
     *                     um RESULTADO de erro antes do fim da transferência
     */
    private PacoteUpload enviarEEsperar(DatagramSocket socket, InetAddress destino, int porta,
                                        PacoteUpload pacote, boolean esperaResultado) throws IOException {
        byte[] dados = pacote.codificar();
        DatagramPacket saida = new DatagramPacket(dados, dados.length, destino, porta);
        byte[] bufferEntrada = new byte[ProtocoloUpload.TAMANHO_MAXIMO_DATAGRAMA_BYTES + 64];

        for (int tentativa = 1; tentativa <= MAXIMO_TENTATIVAS_POR_PACOTE; tentativa++) {
            if (!deveSimularPerda()) {
                socket.send(saida);
            }
            long prazo = System.nanoTime() + timeoutRespostaMs * 1_000_000L;
            while (true) {
                long restanteMs = (prazo - System.nanoTime()) / 1_000_000L;
                if (restanteMs <= 0) {
                    break; // timeout: retransmite
                }
                socket.setSoTimeout((int) restanteMs);
                DatagramPacket entrada = new DatagramPacket(bufferEntrada, bufferEntrada.length);
                try {
                    socket.receive(entrada);
                } catch (SocketTimeoutException timeout) {
                    break;
                }
                if (deveSimularPerda()) {
                    continue; // resposta "perdida" na rede
                }
                PacoteUpload resposta;
                try {
                    resposta = PacoteUpload.decodificar(entrada.getData(), entrada.getLength());
                } catch (IllegalArgumentException invalido) {
                    continue;
                }
                if (resposta.getIdTransferencia() != pacote.getIdTransferencia()) {
                    continue;
                }
                if (resposta.getTipo() == ProtocoloUpload.TIPO_RESULTADO) {
                    if (esperaResultado) {
                        return resposta;
                    }
                    throw new IOException("Servidor abortou a transferência: "
                            + ProtocoloUpload.lerMensagemResultado(resposta.getCarga()));
                }
                if (!esperaResultado && resposta.getTipo() == ProtocoloUpload.TIPO_ACK
                        && resposta.getSequencia() == pacote.getSequencia()) {
                    return resposta;
                }
            }
        }
        throw new IOException("Servidor não respondeu após " + MAXIMO_TENTATIVAS_POR_PACOTE
                + " tentativas (pacote de sequência " + pacote.getSequencia() + ")");
    }

    /**
     * Informa o progresso ao ouvinte, se houver.
     *
     * @param ouvinte  ouvinte ou {@code null}
     * @param enviados bytes confirmados
     * @param totais   bytes totais
     */
    private static void notificar(OuvinteProgresso ouvinte, long enviados, long totais) {
        if (ouvinte != null) {
            ouvinte.aoProgredir(enviados, totais);
        }
    }

    /**
     * Decide, ao acaso, se um pacote deve ser tratado como perdido (somente para testes).
     *
     * @return {@code true} se a perda deve ser simulada
     */
    private boolean deveSimularPerda() {
        double probabilidade = probabilidadePerdaSimulada;
        return probabilidade > 0.0 && ThreadLocalRandom.current().nextDouble() < probabilidade;
    }

    /**
     * Cria o calculador de SHA-1.
     *
     * @return instância de MessageDigest para SHA-1
     */
    private static MessageDigest criarSha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 indisponível na JVM", e);
        }
    }

    /**
     * Converte um tamanho em bytes para texto legível (B, KiB, MiB, GiB).
     *
     * @param bytes quantidade de bytes
     * @return texto como "4.00 MiB"
     */
    public static String formatarTamanho(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        String[] unidades = {"KiB", "MiB", "GiB", "TiB"};
        double valor = bytes;
        int indice = -1;
        while (valor >= 1024 && indice < unidades.length - 1) {
            valor /= 1024;
            indice++;
        }
        return String.format("%.2f %s", valor, unidades[indice]);
    }

    /**
     * Define o tempo de espera por resposta antes de retransmitir.
     *
     * @param milissegundos tempo em ms (maior que zero)
     */
    public void setTimeoutRespostaMs(int milissegundos) {
        this.timeoutRespostaMs = milissegundos;
    }

    /**
     * Gancho de teste: faz o cliente descartar pacotes (enviados e recebidos) ao acaso.
     *
     * @param probabilidade valor de 0.0 (nenhuma perda) a 1.0
     */
    public void setProbabilidadePerdaSimulada(double probabilidade) {
        this.probabilidadePerdaSimulada = probabilidade;
    }

    /**
     * Gancho de teste: envia um SHA-1 propositalmente errado para verificar a rejeição.
     *
     * @param corromper {@code true} para corromper o checksum enviado
     */
    public void setCorromperChecksumParaTeste(boolean corromper) {
        this.corromperChecksumParaTeste = corromper;
    }
}
