=====================================================================
ATIVIDADE 2 - PROGRAMAÇÃO COM SOCKETS UDP
Sistemas Distribuídos - Prof. Rodrigo Campiolo
=====================================================================

Dupla:
  - Pedro Borges de Araujo -> implementação em JAVA   (pasta java/)
  - Daniel Suzuki Naves    -> implementação em PYTHON (pasta python/)

Criação: 07/10/2026        Última atualização: 12/10/2026

As duas implementações seguem o MESMO protocolo (item 6) e foram testadas
uma contra a outra (item 8): peers Java e Python conversam no mesmo chat, e
o cliente de um envia arquivos ao servidor do outro.

---------------------------------------------------------------------
1. O QUE FOI FEITO
---------------------------------------------------------------------
Questão 1 - Chat P2P via UDP
  Mensagens trocadas diretamente entre os clientes (UDP) no formato do
  enunciado:  tipo[1] | tam_apl[1] | apelido[1..64] | tam_msg[1] | mensagem[0..255]
  Tipos: 1 normal, 2 emoji, 3 URL, 4 ECHO.

                                                         JAVA   PYTHON
  a) servidor TCP com a lista de pessoas ativas            sim    sim
  b) remoção da lista ao fechar a conexão TCP              sim    sim
  c) servidor notifica toda mudança de estado (push)       sim    sim
  d) "emotions" com ícones                                 sim    sim

Questão 2 - Upload de arquivos via UDP
  Servidor UDP recebe o arquivo em blocos de 1024 bytes, confere o checksum
  SHA-1 no final e grava na pasta padrão "uploads_recebidos". Como o UDP pode
  perder pacotes, o protocolo usa ACK + retransmissão (parar-e-esperar).

                                                         JAVA   PYTHON
  a) log no servidor (início, término, nome, tamanho,
     origem)                                               sim    sim
  b) interface gráfica no cliente (seleção de arquivo)     sim    não
  c) barra de estado (percentual transferido/restante)     sim    sim (barra no terminal)
  d) transferências simultâneas                            sim    sim (servidor)

  No Python, o cliente envia um arquivo por vez pelo menu; o SERVIDOR aceita
  vários clientes ao mesmo tempo. No Java, o cliente de linha de comando e a
  interface gráfica também enviam vários arquivos simultaneamente.

---------------------------------------------------------------------
2. ESTRUTURA DO REPOSITÓRIO
---------------------------------------------------------------------
  README.txt        este arquivo
  java/             implementação em Java (pacotes "chat" e "upload"), testes
                    automatizados (testes.TestesAtividade) e scripts de compilação
  python/           implementação em Python:
    q1_servidor_lista_ativos.py   servidor TCP da lista de ativos
    q1_chat_peer.py               cliente (peer) do chat
    q2_servidor_upload.py         servidor UDP de upload
    q2_cliente_upload.py          cliente de upload (menu no terminal)
  docs/             especificação dos protocolos (PROTOCOLO_CHAT.txt e
                    PROTOCOLO_UPLOAD.txt), com diagramas

---------------------------------------------------------------------
3. BIBLIOTECAS USADAS
---------------------------------------------------------------------
Nenhuma biblioteca externa (sem Maven, Gradle, pip ou arquivos .jar).

Java (JDK 11 ou superior): somente a biblioteca padrão:
  java.net (DatagramSocket, Socket, ServerSocket), java.security.MessageDigest
  (SHA-1), java.nio.file, java.util.concurrent e javax.swing (interface
  gráfica do cliente de upload, já incluída no JDK).

Python (3.9 ou superior; testado com 3.12): somente a biblioteca padrão:
  socket, struct, hashlib (SHA-1), threading, logging, datetime, os, sys,
  time, random, typing, urllib.parse.

---------------------------------------------------------------------
4. COMO COMPILAR
---------------------------------------------------------------------
Java (requer JDK 11+; "javac -version" deve funcionar). Na raiz do repositório:

  Linux / macOS:
    mkdir -p out
    javac -encoding UTF-8 -d out $(find java -name "*.java")

  Windows (Prompt de Comando):
    mkdir out
    dir /s /b java\*.java > fontes.txt
    javac -encoding UTF-8 -d out @fontes.txt

  O -encoding UTF-8 é necessário (os fontes têm acentos e emojis).
  Os .class são gerados em "out".

Python: não há compilação. Basta ter o Python 3.9+ ("python3 --version").

---------------------------------------------------------------------
5. COMO EXECUTAR
---------------------------------------------------------------------
Em todos os comandos, abra um terminal por programa. Portas padrão:
TCP 5000 (lista de ativos) e UDP 6000 (upload). Em Windows, use "python"
no lugar de "python3". Para acentos e emojis aparecerem corretamente:
  Java:   java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp out ...
  Python: defina PYTHONIOENCODING=utf-8 (Windows: set PYTHONIOENCODING=utf-8)

--- Questão 1: chat P2P ---------------------------------------------
1) Servidor da lista de ativos (use UM dos dois; qualquer peer funciona com ambos):
     Java:    java -cp out chat.ServidorListaAtivos [portaTcp]
     Python:  python3 python/q1_servidor_lista_ativos.py [portaTcp]

2) Cada participante (cada um com apelido e porta UDP próprios):
     Java:    java -cp out chat.ChatPeer <apelido> <portaUdp> [hostServidor] [portaServidor]
     Python:  python3 python/q1_chat_peer.py <apelido> <portaUdp> [hostServidor] [portaServidor]
   Em computadores diferentes, informe o IP do servidor, por exemplo:
     java -cp out chat.ChatPeer ana 7101 192.168.0.10 5000
   (libere no firewall as portas TCP 5000 e as portas UDP dos peers)

   Comandos do chat (texto sem "/" é enviado como mensagem normal):
     /emoji <nome>     envia um emoji (tipo 2)            ex.: /emoji joinha
     /emojis           lista os nomes de emoji
     /url <endereço>   envia uma URL http/https (tipo 3)
     /lista            mostra os participantes conhecidos
     /ativos           mostra o estado dos ECHOs (quem está ativo)
     /ajuda            mostra os comandos
     /sair             sai do chat (remove da lista do servidor)
   Dentro de uma mensagem normal, :feliz: :coracao: :joinha: :fogo: etc. viram ícones.
   (Os nomes de emoji aceitos variam um pouco entre Java e Python; use /emojis.)

--- Questão 2: upload via UDP ----------------------------------------
1) Servidor (porta UDP padrão 6000, pasta "uploads_recebidos", log "servidor_upload.log"):
     Java:    java -cp out upload.ServidorUpload [porta] [pastaDestino] [arquivoLog]
     Python:  python3 python/q2_servidor_upload.py [porta] [pastaDestino] [arquivoLog]

2) Cliente:
     Java (linha de comando, um ou mais arquivos ao mesmo tempo):
       java -cp out upload.ClienteUploadCli [--perda=0.1] <host> <porta> <arquivo>...
       (--perda=X, de 0 a 1, simula perda de pacotes para mostrar a retransmissão)
     Java (interface gráfica, com seleção de arquivos e barra de estado):
       java -cp out upload.ClienteUploadGui
     Python (menu no terminal; opção 1 envia um arquivo, opção 2 troca servidor/porta):
       python3 python/q2_cliente_upload.py
       (o servidor padrão do menu é 127.0.0.1:6000)

---------------------------------------------------------------------
6. PROTOCOLOS (RESUMO; DETALHES EM docs/)
---------------------------------------------------------------------
Chat - mensagem UDP entre peers (um datagrama por mensagem):
   tipo[1] | tam_apl[1] | apelido[tam_apl, 1..64] | tam_msg[1] | mensagem[tam_msg, 0..255]
   Tamanhos em BYTES, sem sinal; textos em UTF-8.
   ECHO (tipo 4): o peer A envia {4, "A", "echo"} aos outros a cada 5 s. Quem recebe
   um ECHO de OUTRO apelido devolve a MESMA mensagem; quando A recebe um ECHO com o
   próprio apelido, sabe que aquele peer está ativo e não responde de novo. Sem
   resposta por 15 s, o cliente exibe um aviso.

Chat - servidor TCP da lista (texto, uma linha por comando, UTF-8, "\n"):
   Cliente -> Servidor:  ENTRAR <apelido> <portaUdp>  |  LISTAR  |  SAIR
   Servidor -> Cliente:  OK  |  ERRO <motivo>  |  LISTA <n> + n linhas "<apelido> <ip> <portaUdp>"
   Sempre que a lista muda, o servidor envia "LISTA n" a todos os clientes conectados.
   Fechar a conexão (ou SAIR) remove o participante. Apelidos são únicos.

Upload - pacote UDP (big-endian):
   tipo[1] | idTransferencia[4] | sequencia[4] | carga[0..1024]
   Tipos: 1 INICIO (seq 0; carga = tamanho[8] + tamanhoNome[2] + nome UTF-8)
          2 DADOS  (seq 1..N; blocos de 1024 bytes, o último com o restante)
          3 FIM    (seq N+1; carga = SHA-1 de 20 bytes)
          4 ACK    (seq do pacote confirmado)
          5 RESULTADO (carga = status[1] + mensagem; 0 OK, 1 checksum divergente, 2 erro)
   O cliente retransmite cada pacote após 300 ms sem resposta (até 40 vezes). O
   servidor grava em um .part e só renomeia se tamanho e SHA-1 conferirem; nunca
   sobrescreve (usa nome_1.ext, nome_2.ext...) e sanitiza o nome ("../x" vira "x").

---------------------------------------------------------------------
7. EXEMPLOS DE USO
---------------------------------------------------------------------
Chat (3 terminais; aqui um peer Java e um Python no mesmo chat):

  Terminal 1:  python3 python/q1_servidor_lista_ativos.py
     [servidor-lista] 20:40:41 - Escutando na porta TCP 5000...
     [servidor-lista] 20:40:42 - Entrou: ana (127.0.0.1:7201)
     [servidor-lista] 20:40:43 - Entrou: bruno (127.0.0.1:7202)

  Terminal 2:  java -cp out chat.ChatPeer ana 7201
     [sistema] conectado como 'ana' (UDP 7201). Digite /ajuda.
     [sistema] bruno entrou no chat
     oi do Java :feliz:
     [você] oi do Java 😀
     [bruno] oi do Python 👍
     [bruno] compartilhou um link: https://github.com

  Terminal 3:  python3 python/q1_chat_peer.py bruno 7202
     [sistema] Conectado como 'bruno' (UDP 7202). Digite /ajuda para ver os comandos.
     [ana] oi do Java 😀
     oi do Python :joinha:
     [você] oi do Python 👍
     /url https://github.com
     [você] https://github.com

Upload (2 terminais):

  Terminal 1:  java -cp out upload.ServidorUpload          (ou o servidor Python)
  Terminal 2:  java -cp out upload.ClienteUploadCli localhost 6000 foto.png relatorio.pdf
     [foto.png] 100% enviado (4.00 MiB de 4.00 MiB)
     [foto.png] SUCESSO - arquivo salvo como foto.png sha1=ec4d054f...
  Cliente Python:  python3 python/q2_cliente_upload.py  ->  opção 1  ->  caminho do arquivo
     [██████████████████████████████] 100.00% (4194304/4194304 bytes)
     [SUCESSO] Servidor confirmou o recebimento: Arquivo salvo como foto.png sha1=...
  Os arquivos aparecem em uploads_recebidos/ e o log em servidor_upload.log:
     [...] INICIO horario=... origem=127.0.0.1:48989 arquivo=foto.png tamanho=4194304
     [...] FIM inicio=... fim=... origem=127.0.0.1:48989 arquivo=foto.png tamanho=4194304
           recebido=4194304 status=OK salvo_como=foto.png ...
  Para conferir a integridade manualmente:  sha1sum foto.png uploads_recebidos/foto.png

---------------------------------------------------------------------
8. CASOS DE TESTE
---------------------------------------------------------------------
8.1 Testes automatizados do código Java (sem bibliotecas externas), com a pasta
    "out" já compilada:
      java -cp out testes.TestesAtividade
    Termina com código 0 se tudo passar (47 verificações). Cobertura:
    Chat   - ida e volta dos 4 tipos; layout dos bytes; limites (apelido 1..64,
             mensagem 0..255); rejeição de apelido vazio/65 bytes, mensagem de 256
             bytes, tipo inválido, datagrama curto/inconsistente; truncamento UTF-8;
             emojis; troca real de datagrama UDP; servidor TCP (registro,
             notificação ao entrar, apelido repetido, LISTAR, remoção ao desconectar).
    Upload - arquivos binários de 0 B, 100 B, 1024 B, 1025 B, 4 KiB e 4 MiB e um
             texto, comparados byte a byte; nome repetido não sobrescreve; log;
             recuperação com 15% de perda de pacotes; 5 transferências simultâneas;
             checksum divergente (arquivo descartado, sem .part); sanitização de
             nomes ("../../etc/passwd" vira "passwd").

8.2 Testes de interoperabilidade Java <-> Python (executados manualmente):
    Upload, nos dois sentidos (cliente Java -> servidor Python e cliente Python ->
      servidor Java): arquivos de 0 B, 100 B, 1025 B, 4 KiB, 4 MiB e um texto com
      acentos chegaram idênticos byte a byte (conferido com cmp). Cliente Java
      com --perda=0.2 contra o servidor Python também concluiu com sucesso. Seis
      clientes Python simultâneos contra o servidor Java: todos íntegros.
    Chat: servidor Python com peers Java e Python, e servidor Java com peers Python e
      Java: mensagens normais, emoji, URL, ECHO (/ativos) e notificações de entrada e
      saída funcionaram entre as duas linguagens.

8.3 Testes manuais sugeridos:
    - Chat: abrir 3 peers; fechar um com Ctrl+C e ver os outros serem notificados;
      deixar um peer parado mais de 15 s (kill -STOP) e ver o aviso de ECHO.
    - Upload: enviar um arquivo grande e interromper o cliente no meio; o servidor
      descarta o .part após 30 s sem atividade.
    - Upload, Java: java -cp out upload.ClienteUploadCli --perda=0.2 localhost 6000 arq.pdf

---------------------------------------------------------------------
9. DECISÕES DE PROJETO E LIMITAÇÕES
---------------------------------------------------------------------
 - O formato das mensagens do chat segue exatamente o enunciado. O protocolo TCP da
   lista de ativos e o de upload foram definidos pela dupla e estão descritos acima
   e em docs/; as duas implementações os seguem, por isso interoperam.
 - Chat: o IP de cada participante é o que o servidor TCP enxerga na conexão. Mensagens
   com mais de 255 bytes são truncadas (com aviso).
 - Upload: parar-e-esperar é simples e confiável, mas mais lento que janela deslizante
   quando a latência é alta (em localhost, 4 MiB levam cerca de 0,5 s). O servidor
   processa os pacotes em uma única thread de recepção; transferências simultâneas
   são intercaladas, cada uma com estado próprio.
 - Python, upload: o cliente não possui interface gráfica (opcional 2.b) e envia um
   arquivo por vez pelo menu.
 - Não há criptografia nem autenticação (fora do escopo da atividade).
