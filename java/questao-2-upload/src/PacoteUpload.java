/*
 * Arquivo....: PacoteUpload.java
 * Descrição..: Pacote do protocolo de upload via UDP (Questão 2). Formato (ordem de rede,
 *              big-endian):
 *
 *                +-----------+----------------------+------------------+-----------------+
 *                | Tipo [1B] | idTransferencia [4B] | sequencia [4B]   | carga [0..1024] |
 *                +-----------+----------------------+------------------+-----------------+
 *
 * Autor......: Pedro Borges de Araujo
 * Criação....: 07/10/2026
 * Atualizações:
 *   - 07/10/2026: versão inicial.
 */
package upload;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Pacote imutável do protocolo de upload, com conversão de/para bytes.
 */
public final class PacoteUpload {

    private final int tipo;
    private final int idTransferencia;
    private final int sequencia;
    private final byte[] carga;

    /**
     * @param tipo            um dos valores {@code ProtocoloUpload.TIPO_*}
     * @param idTransferencia identificador da transferência (escolhido pelo cliente)
     * @param sequencia       número de sequência (0 = INICIO, 1..N = DADOS, N+1 = FIM)
     * @param carga           conteúdo do pacote (até 1024 bytes); {@code null} equivale a vazio
     * @throws IllegalArgumentException se o tipo for inválido ou a carga grande demais
     */
    public PacoteUpload(int tipo, int idTransferencia, int sequencia, byte[] carga) {
        if (tipo < ProtocoloUpload.TIPO_INICIO || tipo > ProtocoloUpload.TIPO_RESULTADO) {
            throw new IllegalArgumentException("Tipo de pacote inválido: " + tipo);
        }
        byte[] cargaSegura = (carga == null) ? new byte[0] : carga;
        if (cargaSegura.length > ProtocoloUpload.TAMANHO_MAXIMO_CARGA_BYTES) {
            throw new IllegalArgumentException("Carga maior que 1024 bytes");
        }
        this.tipo = tipo;
        this.idTransferencia = idTransferencia;
        this.sequencia = sequencia;
        this.carga = cargaSegura;
    }

    /**
     * Converte o pacote em bytes para envio em um datagrama.
     *
     * @return cabeçalho de 9 bytes seguido da carga
     */
    public byte[] codificar() {
        ByteBuffer buffer = ByteBuffer.allocate(ProtocoloUpload.TAMANHO_CABECALHO_BYTES + carga.length);
        buffer.put((byte) tipo);
        buffer.putInt(idTransferencia);
        buffer.putInt(sequencia);
        buffer.put(carga);
        return buffer.array();
    }

    /**
     * Interpreta bytes de um datagrama como pacote de upload.
     *
     * @param dados           buffer recebido
     * @param quantidadeBytes quantidade de bytes válidos no buffer
     * @return o pacote decodificado
     * @throws IllegalArgumentException se o datagrama for curto demais ou tiver tipo inválido
     */
    public static PacoteUpload decodificar(byte[] dados, int quantidadeBytes) {
        if (quantidadeBytes < ProtocoloUpload.TAMANHO_CABECALHO_BYTES) {
            throw new IllegalArgumentException("Datagrama menor que o cabeçalho");
        }
        ByteBuffer buffer = ByteBuffer.wrap(dados, 0, quantidadeBytes);
        int tipo = buffer.get() & 0xFF;
        int idTransferencia = buffer.getInt();
        int sequencia = buffer.getInt();
        byte[] carga = Arrays.copyOfRange(dados, ProtocoloUpload.TAMANHO_CABECALHO_BYTES, quantidadeBytes);
        return new PacoteUpload(tipo, idTransferencia, sequencia, carga);
    }

    /** @return tipo do pacote */
    public int getTipo() {
        return tipo;
    }

    /** @return identificador da transferência */
    public int getIdTransferencia() {
        return idTransferencia;
    }

    /** @return número de sequência */
    public int getSequencia() {
        return sequencia;
    }

    /** @return cópia da carga do pacote */
    public byte[] getCarga() {
        return carga.clone();
    }
}
