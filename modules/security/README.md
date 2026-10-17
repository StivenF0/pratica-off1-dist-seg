# Módulo `security`

Biblioteca compartilhada de proteção de sessões para os projetos da prática. Usa primitivas padrão do JDK; é uma implementação didática e **não substitui TLS/DTLS nem deve ser apresentada como protocolo de produção**.

## Perfil e protocolo

- RSA-3072 com expoente 65537. O iniciador transporta uma chave AES-256 e uma chave HMAC-SHA-256, independentes, cifradas com RSA-OAEP/SHA-256 e MGF1-SHA-256 explícitos.
- A oferta `KEY_EXCHANGE` inclui projeto, identidades, UUID de sessão e validade curta. RSA-PSS/SHA-256, MGF1-SHA-256, salt de 32 bytes assina o cabeçalho, o material OAEP e o HMAC da oferta. A identidade do iniciador é verificada pelo manifesto local.
- O receptor valida a assinatura, contexto e validade, decifra as chaves, confere o HMAC e só então registra a oferta contra replay. O `READY` cifrado e autenticado prova ao iniciador que o receptor conseguiu recuperar as chaves. Uma sessão só é usada depois dessa confirmação.
- Mensagens normais não usam RSA nem PSS: AES-256-GCM/NoPadding com tag de 128 bits e HMAC-SHA-256 completo de 32 bytes. O HMAC usa uma chave aleatória distinta da chave AES e cobre cabeçalho, ciphertext e tag GCM. O cabeçalho também é AAD do GCM.
- O IV GCM é composto por um prefixo de direção de 32 bits e uma sequência crescente de 64 bits. As direções têm prefixos diferentes; cada sessão mantém uma janela antirreplay de 64 sequências para permitir pequena reordenação UDP. Não se reutiliza sequência/IV com a mesma chave.
- `Cipher`, `Mac` e `Signature` são criados por operação, não compartilhados entre threads. Sessões são somente em memória; `close()` apaga os arrays das chaves e reconexão negocia chaves novas.
- O payload é uma sequência opaca de bytes. JSON e regras de domínio pertencem aos módulos consumidores.

OAEP, GCM e PSS usam parâmetros explícitos; defaults históricos SHA-1 não são usados. Embora GCM já autentique o payload, o HMAC separado é mantido para atender ao requisito explícito do enunciado de Segurança.

## Gerar e confiar em identidades

Gere diretórios separados por identidade. A chave privada nunca deve ser copiada para o manifesto, commitada ou enviada pela rede.

```bash
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-server --directory security-keys/mini-dns/dns-server'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-1 --directory security-keys/mini-dns/dns-client-1'
./gradlew :security:run --args='generate-keys --project mini-dns --identity registrar --directory security-keys/mini-dns/registrar'
./gradlew :security:run --args='create-trust-manifest --project mini-dns --directory security-keys/mini-dns --output security-keys/mini-dns/trust.tsv --identities dns-server,dns-client-1,registrar'
```

Repita a geração para as identidades de cada projeto. A confiança é limitada pelo nome do projeto no manifesto, que inclui somente chaves públicas e fingerprints SHA-256. Inclua no manifesto as identidades locais e remotas necessárias. Distribua o manifesto por canal local confiável e confira fingerprints; chaves recebidas pela rede nunca são aceitas automaticamente.

Os arquivos privados PKCS#8 têm permissão POSIX `0600` e diretórios de identidade `0700` quando suportado. A biblioteca não cifra chaves privadas em repouso: proteja o diretório e gere chaves novas por ambiente. No Windows, ajuste permissões pelo controle de acesso nativo.

Formato do manifesto, UTF-8, separado por tabulações:

```text
security-trust-v1<TAB>projeto
identidade<TAB>caminho-chave-OAEP<TAB>fingerprint-SHA256<TAB>caminho-chave-PSS<TAB>fingerprint-SHA256
```

Os caminhos são relativos ao manifesto e não podem escapar do diretório. Chaves públicas são X.509/SPKI; privadas são PKCS#8. O carregador confere projeto, formato, tamanho RSA, duplicatas, caminhos e fingerprints.

## API TCP

O canal exige handshake; não existe construtor para enviar um envelope isolado sem sessão. O socket cliente e o socket aceito pelo servidor devem ser conectados e usados assim:

```java
SecureTcpChannel client = SecureTcpChannel.connect(socket, local, trust, "dns-server", replayGuard);
client.send(payload);
OpenedMessage reply = client.receive();

SecureTcpChannel server = SecureTcpChannel.accept(acceptedSocket, local, trust, replayGuard);
OpenedMessage request = server.receive();
server.send(response);
```

O exemplo omite `try-with-resources`. Cada canal usa prefixo TCP de comprimento de quatro bytes e limite de 1 MiB; trata leituras parciais, frames concatenados e EOF no meio do frame. Uma falha criptográfica fecha apenas a conexão afetada. Configure `Socket.setSoTimeout` para o tempo limite desejado das operações; o handshake usa 10 segundos quando o socket não tem timeout configurado e depois restaura a configuração anterior.

## API UDP

O cliente chama `connect(target, recipient)` e só envia após receber e validar `READY`. O receptor chama `receive()`: a chegada da oferta autenticada instala a sessão, envia `READY` e a chamada retorna somente quando uma mensagem de aplicação válida chegar.

```java
SecureSession session = client.connect(serverAddress, "dns-server");
client.send(session, request);

ReceivedDatagram request = server.receive();
server.send(request.session(), response);
```

`ReceivedDatagram` informa endereço de origem, sessão autenticada e `OpenedMessage`. As respostas devem usar `request.session()`, não criar outra mensagem sem vínculo com o par. O endpoint repete a mesma oferta a cada segundo durante o timeout; uma duplicata idêntica recebe os mesmos bytes de `READY`, sem reinstalar chaves ou reiniciar sequências. Uma nova sessão autenticada do mesmo par substitui a antiga; o número de sessões simultâneas é limitado pelas identidades confiáveis no manifesto.

Um datagrama completo não pode exceder 1200 bytes. O endpoint detecta truncamento/excesso, rejeita frames maiores e descarta pacotes inválidos sem encerrar o listener. `receive()` pode bloquear conforme `DatagramSocket.setSoTimeout`. Sem fragmentação ou garantia de entrega UDP.

Para as notificações Mini-DNS, `sendMulticast(group, sessions, payload)` empacota exatamente três frames AES/HMAC independentes, um por sessão, em um único datagrama de até 1200 bytes. O receptor deve criar um `MulticastSocket`, associá-lo ao grupo/interface e passá-lo ao endpoint; `receive()` reconhece o contêiner e valida o registro correspondente à sessão local. Não se compartilham chaves de grupo. O payload multicast máximo decorre do limite do pacote e do tamanho dos três registros.

## Replay, falhas e logs

`ReplayGuard` protege **ofertas de handshake**: validade máxima de 30 segundos, tolerância de relógio de 2 segundos, limite de 100 mil ofertas e quarentena inicial de 34 segundos após criação/reinício. Aguarde `ReplayGuard.isReady()` antes de iniciar canais/listeners; o prazo limita somente ofertas, não a duração da sessão.

As mensagens da sessão não carregam timestamps nem UUID por mensagem. Cada sentido tem sequência própria; repetição ou sequência antiga autenticada retorna `OpenedMessage.duplicate()` com payload vazio. Os módulos consumidores devem ignorar duplicatas e só autorizar operações com base em `OpenedMessage.sender()` e no contexto do projeto.

Os transportes registram `HMAC_OK` após validar uma oferta, `READY` ou mensagem; registram `HMAC_FAIL` quando a comparação do MAC falha. Logs incluem horário, projeto, identidades, UUID abreviado, direção e tipo, nunca chaves, conteúdo decifrado de handshake ou o HMAC completo. Outros frames inválidos são registrados como `REJECTED`. `HmacValidationException` permite ao módulo consumidor distinguir MAC inválido de assinatura/contexto inválido, sem retransmitir detalhes criptográficos ao remetente.

TCP inválido fecha somente aquele canal. UDP inválido é descartado e o listener continua. `SecureSession.open()` só retorna depois de verificar HMAC com `MessageDigest.isEqual` e a tag GCM; nenhum payload não autenticado alcança o domínio.

## Garantias e limitações

- RSA-OAEP transporta chaves no estabelecimento; PSS autentica o iniciador pelo manifesto e `READY` autentica o receptor por posse da chave de transporte. AES-256-GCM protege confidencialidade/integridade; HMAC separado cumpre a verificação explícita do enunciado.
- HMAC autentica mensagens somente entre as duas pontas que compartilham a chave; não oferece assinatura pública, não repúdio ou prova a terceiros. Autorização de operações cabe a cada projeto.
- O protocolo não foi revisado formalmente, não é equivalente a TLS/DTLS, não é pós-quântico e não oferece forward secrecy com transporte RSA duradouro. Uma chave privada comprometida pode revelar sessões gravadas.
- Chaves privadas PKCS#8 não são cifradas em repouso. Distribuição de chaves públicas e manifestos requer canal confiável. Não há certificados, PKI, renovação automática, rotação em segundo plano ou negociação de algoritmos.
- A janela UDP aceita no máximo 64 posições de reordenação; perda de pacotes permanece possível. A biblioteca não reenvia comandos de domínio.

## Testes

```bash
./gradlew :security:test
./gradlew check
```

Os testes cobrem oferta OAEP/PSS, confirmação HMAC, mensagens AES/HMAC em sequência, falha de HMAC sem consumir sequência, replay e reordenação, confiança/fingerprints, limites TCP/UDP e troca TCP/UDP entre JVMs separadas.
