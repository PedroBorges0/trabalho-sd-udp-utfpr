/*
 * Arquivo....: ProtocoloUpload.java
 * Descrição..: Constantes e funções auxiliares do protocolo de upload de arquivos via
 *              UDP (Questão 2). Define tipos de pacote, tamanhos e a montagem/leitura
 *              das cargas (payloads) dos pacotes INICIO e RESULTADO.
 *              A especificação completa (com diagramas) está em docs/PROTOCOLO_UPLOAD.txt.
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package upload;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Definições compartilhadas por cliente e servidor de upload.
 */
public final class ProtocoloUpload {

    /** Tipo 1: abre a transferência (nome e tamanho do arquivo). */
    public static final int TIPO_INICIO = 1;
    /** Tipo 2: bloco de dados do arquivo. */
    public static final int TIPO_DADOS = 2;
    /** Tipo 3: fim da transferência (carga = checksum SHA-1 de 20 bytes). */
    public static final int TIPO_FIM = 3;
    /** Tipo 4: confirmação (ACK) de INICIO ou DADOS. */
    public static final int TIPO_ACK = 4;
    /** Tipo 5: resultado final enviado pelo servidor (ou erro que aborta a transferência). */
    public static final int TIPO_RESULTADO = 5;

    /** Resultado: arquivo recebido, checksum conferido e arquivo salvo. */
    public static final int STATUS_OK = 0;
    /** Resultado: o SHA-1 calculado pelo servidor difere do enviado pelo cliente. */
    public static final int STATUS_CHECKSUM_DIVERGENTE = 1;
    /** Resultado: erro genérico (pacote inválido, falha de disco, etc.). */
    public static final int STATUS_ERRO = 2;

    /** Tamanho de cada bloco de dados do arquivo, conforme o enunciado. */
    public static final int TAMANHO_BLOCO_DADOS_BYTES = 1024;
    /** Cabeçalho: tipo (1) + idTransferencia (4) + sequencia (4). */
    public static final int TAMANHO_CABECALHO_BYTES = 9;
    /** Maior carga permitida em qualquer pacote. */
    public static final int TAMANHO_MAXIMO_CARGA_BYTES = 1024;
    /** Maior datagrama possível: cabeçalho + carga máxima. */
    public static final int TAMANHO_MAXIMO_DATAGRAMA_BYTES = TAMANHO_CABECALHO_BYTES + TAMANHO_MAXIMO_CARGA_BYTES;
    /** Tamanho do checksum SHA-1. */
    public static final int TAMANHO_SHA1_BYTES = 20;
    /** Maior nome de arquivo aceito, em bytes UTF-8. */
    public static final int TAMANHO_MAXIMO_NOME_ARQUIVO_BYTES = 255;

    private ProtocoloUpload() {
        // Classe utilitária: não deve ser instanciada.
    }

    /**
     * Calcula quantos blocos de 1024 bytes são necessários para um arquivo.
     *
     * @param tamanhoArquivoBytes tamanho do arquivo em bytes (&gt;= 0)
     * @return quantidade de blocos (0 para arquivo vazio)
     * @throws IllegalArgumentException se o tamanho for negativo ou grande demais
     */
    public static int calcularTotalBlocos(long tamanhoArquivoBytes) {
        if (tamanhoArquivoBytes < 0) {
            throw new IllegalArgumentException("Tamanho de arquivo negativo");
        }
        long total = (tamanhoArquivoBytes + TAMANHO_BLOCO_DADOS_BYTES - 1) / TAMANHO_BLOCO_DADOS_BYTES;
        if (total > Integer.MAX_VALUE - 2) {
            throw new IllegalArgumentException("Arquivo grande demais para o protocolo");
        }
        return (int) total;
    }

    /**
     * Calcula o tamanho esperado de um bloco: 1024 bytes, exceto o último, que leva o restante.
     *
     * @param tamanhoArquivoBytes tamanho total do arquivo
     * @param numeroBloco         número do bloco, de 1 até o total de blocos
     * @return tamanho esperado do bloco, em bytes
     */
    public static int calcularTamanhoDoBloco(long tamanhoArquivoBytes, int numeroBloco) {
        long inicio = (long) (numeroBloco - 1) * TAMANHO_BLOCO_DADOS_BYTES;
        return (int) Math.min(TAMANHO_BLOCO_DADOS_BYTES, tamanhoArquivoBytes - inicio);
    }

    /**
     * Monta a carga do pacote INICIO: tamanho do arquivo (8 bytes), tamanho do nome (2 bytes)
     * e nome do arquivo em UTF-8.
     *
     * @param nomeArquivo         nome do arquivo (sem diretório)
     * @param tamanhoArquivoBytes tamanho do arquivo em bytes
     * @return carga pronta para o pacote INICIO
     * @throws IllegalArgumentException se o nome for vazio ou longo demais
     */
    public static byte[] montarCargaInicio(String nomeArquivo, long tamanhoArquivoBytes) {
        byte[] nomeBytes = nomeArquivo.getBytes(StandardCharsets.UTF_8);
        if (nomeBytes.length == 0 || nomeBytes.length > TAMANHO_MAXIMO_NOME_ARQUIVO_BYTES) {
            throw new IllegalArgumentException("Nome de arquivo deve ter de 1 a 255 bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate(8 + 2 + nomeBytes.length);
        buffer.putLong(tamanhoArquivoBytes);
        buffer.putShort((short) nomeBytes.length);
        buffer.put(nomeBytes);
        return buffer.array();
    }

    /**
     * Interpreta a carga de um pacote INICIO.
     *
     * @param carga carga recebida
     * @return nome e tamanho do arquivo anunciados pelo cliente
     * @throws IllegalArgumentException se a carga estiver malformada
     */
    public static InformacaoArquivo lerCargaInicio(byte[] carga) {
        if (carga.length < 10) {
            throw new IllegalArgumentException("Carga de INICIO curta demais");
        }
        ByteBuffer buffer = ByteBuffer.wrap(carga);
        long tamanho = buffer.getLong();
        int tamanhoNome = buffer.getShort() & 0xFFFF;
        if (tamanho < 0 || tamanhoNome == 0 || carga.length != 10 + tamanhoNome) {
            throw new IllegalArgumentException("Carga de INICIO inconsistente");
        }
        String nome = new String(carga, 10, tamanhoNome, StandardCharsets.UTF_8);
        return new InformacaoArquivo(nome, tamanho);
    }

    /**
     * Monta a carga do pacote RESULTADO: status (1 byte) + mensagem de texto UTF-8.
     *
     * @param status   um dos valores {@code STATUS_*}
     * @param mensagem explicação curta em texto
     * @return carga pronta para o pacote RESULTADO
     */
    public static byte[] montarCargaResultado(int status, String mensagem) {
        byte[] mensagemBytes = mensagem.getBytes(StandardCharsets.UTF_8);
        int tamanhoMensagem = Math.min(mensagemBytes.length, 400);
        ByteBuffer buffer = ByteBuffer.allocate(1 + tamanhoMensagem);
        buffer.put((byte) status);
        buffer.put(mensagemBytes, 0, tamanhoMensagem);
        return buffer.array();
    }

    /**
     * Lê o status de uma carga de RESULTADO.
     *
     * @param carga carga do pacote RESULTADO
     * @return um dos valores {@code STATUS_*}
     */
    public static int lerStatusResultado(byte[] carga) {
        return (carga.length == 0) ? STATUS_ERRO : (carga[0] & 0xFF);
    }

    /**
     * Lê a mensagem de texto de uma carga de RESULTADO.
     *
     * @param carga carga do pacote RESULTADO
     * @return mensagem (vazia se não houver)
     */
    public static String lerMensagemResultado(byte[] carga) {
        return (carga.length <= 1) ? "" : new String(carga, 1, carga.length - 1, StandardCharsets.UTF_8);
    }

    /** Nome e tamanho de um arquivo anunciados no pacote INICIO. */
    public static final class InformacaoArquivo {
        private final String nome;
        private final long tamanhoBytes;

        /**
         * @param nome         nome do arquivo
         * @param tamanhoBytes tamanho em bytes
         */
        public InformacaoArquivo(String nome, long tamanhoBytes) {
            this.nome = nome;
            this.tamanhoBytes = tamanhoBytes;
        }

        /** @return nome do arquivo anunciado */
        public String getNome() {
            return nome;
        }

        /** @return tamanho do arquivo em bytes */
        public long getTamanhoBytes() {
            return tamanhoBytes;
        }
    }
}
