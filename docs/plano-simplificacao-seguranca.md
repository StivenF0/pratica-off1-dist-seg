# Plano de simplificação do módulo `security`

## Objetivo, escopo e resultado

Reduzir a infraestrutura própria e deixar visível o uso das APIs de criptografia e dos
sockets do Java. A simplificação foi aplicada somente a `security` e Mini-DNS; os outros
projetos não foram integrados. `./gradlew check` e os launchers de ambos os módulos
passaram. A demonstração manual em processos separados não foi executada.

## O que não muda

- RSA-OAEP no estabelecimento da sessão; AES-GCM nas mensagens; HMAC-SHA-256 conforme
  o enunciado; assinatura RSA-PSS nas comunicações conforme o diagrama do grupo.
- Pares RSA separados para OAEP e PSS, arquivos de chave existentes e chaves privadas
  mantidas localmente. Não regenerar nem apagar chaves durante a simplificação.
- Validação de identidade, formato e tamanho das chaves, do HMAC, da assinatura e da
  tag GCM antes de entregar dados à aplicação. Sem aceitar chave recebida pela rede,
  fallback para texto claro ou log de segredos.
- Um perfil criptográfico fixo usando as APIs do JDK (`Cipher`, `Mac`, `Signature`,
  `KeyPairGenerator` e `SecureRandom`); sem implementar algoritmos à mão ou adicionar
  opções de negociação.
- Contador de envio por direção/sessão para produzir nonces GCM diferentes.

## Mudanças aplicadas: antes → agora

| Área | Antes | Agora |
| --- | --- | --- |
| Confiança em identidades | `TrustStore` carrega `trust.tsv`, fingerprints, projeto e caminhos de chaves; `SecurityCli` também cria o manifesto. | Carregar as chaves públicas OAEP/PSS dos participantes a partir de configuração/arquivos locais simples. Remover geração/leitura de manifesto e fingerprints pelo programa. Continuar exigindo confiança configurada localmente; nunca confiar automaticamente numa chave recebida pela rede. |
| Chaves locais | `LocalIdentity`/`KeyFiles` carregam e validam dois pares RSA por identidade. | Manter esse comportamento e formato. Manter o comando de geração de chaves; remover apenas o comando de criar manifesto. |
| Criptografia compartilhada | `SecureHandshake` e `SecureSession` estabelecem sessões e criam/abrem frames; a API está acoplada aos transportes atuais. | Manter uma API curta para carregar identidade, estabelecer/confirmar sessão e proteger/abrir bytes. Não criar outra implementação das primitivas. |
| Transporte | `SecureTcpChannel` e `SecureUdpEndpoint` fazem leitura/escrita de sockets, enquadramento, timeout, retry UDP, multicast, associação de sessões e parte dos logs. | Retirar esses wrappers genéricos. Cada aplicação usa `Socket`, `DatagramSocket`/`MulticastSocket` e threads diretamente; o módulo `security` não abre sockets nem decide como reenviar, ouvir multicast ou tratar mensagens de domínio. |
| Resultado UDP | `ReceivedDatagram` combina pacote de rede, sessão e mensagem aberta. | A aplicação usa o endereço e os bytes do `DatagramPacket` que recebeu e chama a API de sessão. Não manter um tipo genérico só para esconder o socket. |
| Replay | `ReplayGuard` valida ofertas, mantém cache de IDs e aplica validade/quarentena; `SecureSession` mantém janela de 64 sequências recebidas. | Remover `ReplayGuard`, cache, validade/quarentena e janela de recebimento. Manter apenas o contador local por direção/sessão que forma o nonce GCM. Mensagem válida repetida poderá executar novamente. |
| Logs | `SecurityAudit` e os wrappers registram resultados de validação. | Registrar no projeto consumidor os eventos necessários (`HMAC_OK`, `HMAC_FAIL`, envio/recebimento), sem imprimir chaves ou conteúdo secreto. Preservar o descarte de mensagens inválidas. |
| Testes | `SecureSessionTest` também cobre wrappers e manifesto; `SecurityMultiprocessTest` inicia JVMs de teste. | Manter poucos testes de identidade/sessão: ida e volta, adulteração de HMAC, assinatura inválida e rejeição de identidade não confiável. Demonstrar processos e cenários dos projetos manualmente. Não remover nem “consertar” nesta etapa o tratamento de `Assumptions` do teste multicast, que foi deixado para depois. |

## Replay: decisão e risco conhecido

A decisão registrada é remover toda a camada de replay: `ReplayGuard`, cache de ofertas,
validade/quarentena de 34 segundos e a janela de 64 sequências recebidas em
`SecureSession`. Fica somente o contador de envio por direção/sessão necessário para
formar nonces GCM diferentes enquanto aquela instância da sessão envia mensagens. Uma
mensagem válida reapresentada poderá executar a operação outra vez. Isso não é exigido
pelo PDF nem aparece nos exemplos do professor.

**Risco técnico que não foi apontado na recomendação anterior:** a oferta atual do
handshake transporta as próprias chaves AES/HMAC. Se uma oferta válida for reapresentada,
o destinatário pode recriar a mesma sessão e reiniciar o contador; isso pode reutilizar
um nonce AES-GCM com a mesma chave. Portanto, o contador preserva unicidade dentro de
uma sessão em execução, mas não protege contra a repetição de uma oferta antiga. Remover
esse risco exigiria redesenhar o handshake, por exemplo para vincular a oferta a um
desafio novo do destinatário; esse redesenho não faz parte da simplificação escolhida.
Não apresentar o resultado como seguro contra replay ou como protocolo de produção.

## Arquivos afetados

- `modules/security/.../identity/TrustStore.java`, `TrustedIdentity.java` e
  `cli/SecurityCli.java`: substituir o manifesto pela leitura local simples de chaves;
  manter `LocalIdentity.java` e `KeyFiles.java` para os pares locais separados.
- `modules/security/.../communication/SecureTcpChannel.java`,
  `SecureUdpEndpoint.java`, `ReceivedDatagram.java`, `SecurityAudit.java` e
  `ReplayGuard.java`: remover as abstrações de transporte e replay. Em
  `SecureHandshake.java`, remover parâmetros/campos usados apenas por `ReplayGuard`;
  em `SecureSession.java`, remover a janela de recebimento e o resultado
  `OpenedMessage.duplicate()`. Manter/refatorar handshake e sessão como API
  criptográfica curta, com contador de envio para os nonces.
- `modules/mini-dns/.../MiniDnsCli.java` e `MiniDnsServer.java`: trocar chamadas aos
  endpoints genéricos por sockets explícitos e chamadas à sessão. Preservar handshake,
  validação antes do domínio, limite de datagrama necessário, sessões individuais no
  multicast e os cenários funcionais do Mini-DNS.
- `modules/security/src/test/...`: reduzir os testes conforme a tabela; retirar os
  testes que só exercitam wrappers excluídos. Atualizar testes do Mini-DNS apenas para
  acompanhar a nova API, sem mudar agora a decisão pendente sobre o teste multicast.
- Atualizar `modules/security/README.md`, `modules/mini-dns/README.md`,
  `docs/padrao-criptografia-hibrida.md` e as partes de segurança de
  `docs/pratica-off1-plano-implementacao.md` para não documentarem manifesto, wrappers
  ou API removidos. Esses documentos só serão alterados durante a implementação.

## Implementação e validação

- Configuração local simples de chaves; os arquivos de chave existentes não foram
  regenerados nem apagados.
- `security` agora expõe identidade, handshake e `seal/open`; os projetos fazem o
  transporte diretamente.
- Mini-DNS foi adaptado para sockets UDP/multicast explícitos.
- `./gradlew check` e `./gradlew :security:installDist :mini-dns:installDist` passaram.
- A demonstração manual entre processos continua pendente. O tratamento de
  `Assumptions` no teste multicast foi mantido e não foi revisado.

## Limitações aceitas

- Repetir um frame de aplicação válido pode repetir a operação, conforme a decisão
  acima; os consumidores devem considerar esse limite ao executar operações.
- Repetir uma oferta de handshake pode reinstalar chaves de sessão e reutilizar nonce
  AES-GCM; evitar esse risco exigiria mudar o handshake, fora do escopo atual.
- Multicast UDP não garante entrega. Cada destinatário continua recebendo conteúdo
  protegido pela própria sessão, não por uma chave de grupo.
- A implementação é didática e não substitui TLS/DTLS nem é um protocolo de produção.
