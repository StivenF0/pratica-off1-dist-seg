# Plano de implementação — Prática Offline 1

## 1. Objetivo, fontes e decisões confirmadas

Planejar quatro aplicações independentes de Sistemas Distribuídos, todas usando uma biblioteca compartilhada de comunicação protegida com RSA e AES. Este documento é um plano, não uma implementação.

- Autores do trabalho: Stiven Felipe e Robert Luann.
- Enunciado: `docs/pratica-offline-1-2026-2.pdf`, especialmente páginas 2–6; apresentação na página 7.
- Organização: `README.md` e configuração Gradle existente.
- Requisito adicional informado pelo usuário: toda comunicação entre processos deve usar RSA e AES.
- Decisões confirmadas pelo usuário: Java 21, interface de terminal, processos separados, execução inicial em localhost e criptografia híbrida explícita, em vez de apenas TLS/DTLS.
- Entrega indicada no PDF: **20/10/2026, até 23h59**, pelo SIGAA; vídeo de até **8 minutos**.
- Plano elaborado em 17/10/2026. A divisão em etapas precisa considerar o prazo curto.

**Destino do documento:** salvo inicialmente em `/home/robert/.opencode/plan/pratica-off1-plano-implementacao.md`, conforme autorizado pelo usuário e permitido pelo modo de planejamento. Após trocar para um agente com permissão de escrita no repositório, copiar para `docs/plano-implementacao.md`.

## 2. Situação encontrada no repositório

| Item | Estado observado | Consequência |
| --- | --- | --- |
| JDK | OpenJDK 21.0.12.1 disponível | Usar toolchain Java 21 |
| Build raiz | Somente plugin `base` | Configurar aplicações, biblioteca, testes e agregação |
| Gradle Wrapper | Aponta para Gradle 9.8.1 | Validar execução e compatibilidade na implementação, sem trocar a versão preventivamente |
| `settings.gradle.kts` | Inclui `mini-dns` e `service-discovery`; outros dois comentados | Habilitar `p2p-naming`, `cdn` e incluir `security` |
| Módulos | Quatro diretórios com apenas `.gitkeep` | Não existe lógica de aplicação a preservar ou migrar |
| Catálogo de versões | Sem bibliotecas declaradas | Fixar versões compatíveis de JSON e testes |
| Documentação | README e PDF | Acrescentar instruções operacionais, protocolo e apresentação |
| Git | `docs/` aparece como não rastreado | Preservar o PDF existente; não sobrescrever nem remover arquivos do usuário |

Não foi executado Gradle nem qualquer build nesta etapa: isso poderia escrever caches e artefatos fora da pasta permitida no modo de planejamento. Nenhuma funcionalidade está validada por execução neste momento.

## 3. Arquitetura e limites de compartilhamento

```text
modules/
  security/           biblioteca de proteção de mensagens TCP/UDP
  mini-dns/           servidor UDP, três clientes e registrador
  service-discovery/  diretório, três calculadoras e três clientes
  p2p-naming/         seis nós TCP em anel
  cdn/                origem, três edges, router e cliente
```

Cada aplicação terá seu próprio `build.gradle.kts`, fontes, testes, configuração, CLI e instruções de execução. Os nomes `p2p-naming` e `cdn` já estão previstos no Gradle e serão mantidos.

```text
mini-dns -----------> security
service-discovery --> security
p2p-naming --------> security
cdn ---------------> security
```

- Não haverá dependências entre os quatro projetos de Sistemas Distribuídos.
- A CDN terá seu próprio router; não dependerá do Mini-DNS nem do diretório de serviços.
- O anel não dependerá de diretório, DNS da prática ou processo coordenador em execução.
- A biblioteca de segurança será carregada em cada processo; não será um servidor adicional.
- Compartilhar configuração de build e versões não significa compartilhar estado ou lógica de domínio.
- Não criar um módulo genérico `common`: consultas, operações, arquivos, caches, roteamento e políticas de autorização pertencem aos respectivos projetos.
- `security` poderá conter enquadramento de mensagens e adaptadores TCP/UDP necessários à comunicação protegida, mas não regras dos exercícios.

### Stack proposta

- Java 21; Gradle Kotlin DSL; `application` nos quatro projetos e `java-library` em `security`.
- Sockets reais: `DatagramSocket`, `DatagramPacket`, `ServerSocket` e `Socket`.
- Threads com `ThreadPoolExecutor` e filas limitadas; tarefas periódicas com `ScheduledExecutorService`.
- Criptografia pelas APIs JCA/JCE do JDK, sem implementar algoritmos matemáticos manualmente.
- Payloads de domínio em JSON UTF-8, usando biblioteca mantida, por exemplo Jackson, com versões fixadas no catálogo.
- JUnit Jupiter para testes; relógio injetável para testar TTL e expiração sem esperas longas.
- Logs em console e arquivo por processo. No P2P, ambos são requisito obrigatório.
- Sem Spring, HTTP, banco externo, interface gráfica ou infraestrutura de nuvem.

## 4. Matriz de requisitos e aceitação

| ID | Requisito | Evidência de conclusão |
| --- | --- | --- |
| DNS-01 | Mapa inicial com dez nomes e endereços | Consultar `servidor1` até `servidor10` retorna os valores do PDF |
| DNS-02 | Três clientes requisitantes | Três processos consultam e permanecem recebendo notificações |
| DNS-03 | Registrador altera `servidor1`, `servidor4`, `servidor9` | Cada um dos três clientes recebe os três novos valores |
| SD-01 | Três servidores de calculadora com quatro operações | Soma, subtração, multiplicação e divisão funcionam em cada servidor |
| SD-02 | Diretório e três clientes; ao menos dois serviços testados | Clientes descobrem e executam, no mínimo, soma e divisão |
| SD-03 | Balanceamento | Round robin distribui solicitações entre três instâncias ativas |
| SD-04 | Descoberta de instâncias ativas | Servidor encerrado expira do diretório e deixa de ser selecionado |
| P2P-01 | Seis processos, predecessor e sucessor | P0–P5 iniciam com a topologia esperada |
| P2P-02 | Sessenta arquivos nas faixas do PDF | Cada nó contém dez nomes e os sessenta são localizáveis |
| P2P-03 | Busca P0 → P1 → P2 → P3 por `arquivo35.ext` | Caminho e resposta a P0 aparecem nos logs |
| P2P-04 | Entradas inválidas não circulam | `arquivo99.ext` e `arquivoABC.ext` imprimem a mensagem exigida e não geram busca na rede |
| P2P-05 | Logs enviados/recebidos armazenados e impressos | Arquivo e console de cada nó contêm os eventos correspondentes |
| CDN-01 | Origem TCP com mil arquivos locais | Arquivos 1–1000 são gerados no disco e servidos pela origem |
| CDN-02 | Três edges com cache de cem arquivos | Contagem nunca ultrapassa cem; expulsão LRU demonstrável |
| CDN-03 | Router por localização simulada | Regiões configuradas levam a edges diferentes |
| CDN-04 | MISS seguido de HIT | Segunda consulta não acessa a origem; logs e métricas comprovam |
| CDN-05 | Expiração por TTL de dez segundos | Dentro do TTL há HIT; depois há nova busca na origem |
| CDN-06 | Invalidação ativa via TCP | Atualização remove a versão antiga de todos os edges e a próxima consulta retorna MISS e conteúdo novo |
| SEC-01 | RSA e AES em todos os enlaces | Consultas, respostas, registros, notificações, heartbeats, buscas e invalidações usam envelopes protegidos |
| SEC-02 | Autenticidade, integridade e autorização | Chave desconhecida, mensagem adulterada e operação sem permissão são rejeitadas |
| SEC-03 | Proteção contra replay e mensagens malformadas | Repetição não reaplica efeitos; mensagens inválidas não derrubam processos |
| ENT-01 | Execução, explicação e entrega | READMEs reproduzíveis, testes, vídeo de até oito minutos e pacote conforme PDF |

## 5. Biblioteca compartilhada `security`

### 5.1. Modelo de ameaça e limites

Proteger conteúdo de aplicação em trânsito contra leitura, adulteração, falsificação de identidade e repetição de mensagens por um observador da rede. Admitir que processos legítimos e seus arquivos de chaves não foram comprometidos e que as chaves públicas foram provisionadas corretamente antes da execução.

O escopo não inclui criptografia dos arquivos da CDN em repouso, proteção contra administrador da máquina, disponibilidade sob DDoS, anonimato de tráfego, segurança pós-quântica ou prova formal do protocolo.

**Importante:** usar primitivas padronizadas não torna um protocolo próprio equivalente a TLS. A escolha explícita de RSA/AES é didática. Para produção, preferir protocolos e bibliotecas de transporte revisados, como TLS/DTLS. O transporte RSA com chaves privadas duradouras não oferece forward secrecy; a exposição futura da chave privada pode comprometer mensagens gravadas anteriormente. RSA também não é pós-quântico.

“Toda comunicação cifrada” significa todo conteúdo de aplicação entre processos. IPs, portas, tamanho, temporização e um cabeçalho mínimo de segurança permanecem observáveis. Logs locais com resultados não são tráfego de rede e serão explicados separadamente.

### 5.2. Perfil criptográfico único, sem negociação insegura

| Uso | Decisão |
| --- | --- |
| Cifra dos payloads | AES-256-GCM, `AES/GCM/NoPadding` |
| Chave de conteúdo | Nova chave AES aleatória de 256 bits para **cada envelope** |
| IV | 96 bits; gerado com `SecureRandom`; nunca reutilizar chave/IV para nova cifragem |
| Tag GCM | 128 bits |
| Proteção da chave AES | RSA de 3072 bits, expoente 65537, RSAES-OAEP |
| Parâmetros OAEP | SHA-256, MGF1 com SHA-256 e label vazio; todos explícitos |
| Autenticação do remetente | RSASSA-PSS, SHA-256, MGF1/SHA-256, salt de 32 bytes, trailer 1 |
| Separação de finalidade | Pares RSA distintos para transporte de chaves e assinatura, por identidade |
| Aleatoriedade | `SecureRandom` e `KeyGenerator` do JDK |

No Java, não usar `OAEPParameterSpec.DEFAULT` nem `PSSParameterSpec.DEFAULT`, pois seus parâmetros históricos incluem SHA-1. Especificar OAEP e PSS completamente. O nome Java `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` não implica usar ECB nos dados: os dados usam exclusivamente AES-GCM.

Não usar RSA para cifrar arquivos ou JSON diretamente; RSA transporta apenas os 32 bytes da chave AES. Não usar AES-ECB, RSA sem padding, PKCS#1 v1.5 para cifragem, chaves fixas no código ou `java.util.Random` para material criptográfico. O uso de AES-256 não significa que a composição inteira ofereça 256 bits de segurança; RSA-3072 é o fator limitante clássico, aproximadamente 128 bits.

**Por que chave por mensagem:** dispensa negociação de sessão, confirmação e recuperação de handshake em UDP, reduzindo o escopo para o prazo. Em contrapartida, RSA aparece em cada envio e aumenta custo e tamanho dos pacotes. Sessões persistentes com rotação ficam fora da primeira versão.

### 5.3. Identidade, provisionamento e autorização

- Identidades estáveis por projeto, por exemplo `dns-server`, `dns-client-1`, `registrar`, `calc-1`, `P0`, `origin` e `edge-1`.
- CLI genérica em `security` para gerar os dois pares RSA de uma identidade e exportar suas chaves públicas.
- As listas de identidades de cada cenário ficam nos respectivos módulos/scripts, não codificadas na biblioteca.
- Chaves públicas em X.509/SPKI e privadas em PKCS#8, com manifestos locais de confiança vinculando projeto, identidade, finalidade e fingerprint SHA-256.
- Distribuição prévia dos manifestos por arquivos locais confiáveis; não aceitar chave pública anunciada pelo próprio remetente na rede, nem confiar automaticamente no primeiro contato.
- Chaves privadas apenas em diretório local ignorado pelo Git, com permissão `0600` e diretório restrito. Cada processo recebe apenas seus caminhos de chave privada; arquivos públicos não contêm segredos.
- A versão didática pode usar PKCS#8 não cifrado com proteção do sistema de arquivos; isso deve ser declarado como limitação de armazenamento, não como recomendação de produção. Não registrar chaves privadas, chaves AES ou senhas nos logs.
- Não distribuir chaves privadas no pacote final. Fornecer comando/script para gerar material novo e montar os manifestos antes de iniciar a demonstração.
- Rotação manual: parar o cenário, gerar pares novos e substituir manifestos por canal local confiável. Não trocar silenciosamente uma chave fixada.
- A biblioteca informa a identidade autenticada; cada módulo decide a autorização da operação. Exemplo: somente o registrador pode modificar o Mini-DNS, somente calculadoras autorizadas se registram no diretório e somente a origem invalida caches.
- Identidades diferentes não significam isolamento contra o mesmo usuário administrador do localhost; essa limitação deve aparecer na explicação.

### 5.4. Envelope e fluxo de proteção

Envelope binário com campos de comprimento delimitado, limites explícitos e ordem determinística:

```text
cabeçalho: magic, versão, projeto, remetente, destinatário,
           messageId, issuedAt, expiresAt, comprimentos
corpo:     chave AES protegida por RSA, IV, ciphertext com tag GCM
assinatura: RSA-PSS sobre cabeçalho e corpo completos
```

O JSON do domínio, incluindo tipo da operação, nomes, endereços simulados, respostas, correlação e conteúdo, fica dentro do ciphertext. O cabeçalho é autenticado como AAD do GCM. A assinatura inclui também a chave AES protegida e o IV; validar os bytes originais, sem depender de reserialização de JSON.

**Envio:** serializar payload → gerar AES/IV novos → cifrar com GCM e AAD → proteger AES com a chave RSA de transporte do destinatário → assinar envelope → enviar.

**Recepção:** validar limites estruturais → localizar chave pública confiável → verificar assinatura → conferir projeto, destinatário e validade → abrir chave AES → validar GCM → atualizar controle de replay atomicamente → entregar payload e identidade autenticada ao módulo → verificar autorização e validar o domínio.

Não entregar plaintext ao domínio antes de a tag GCM ser validada. Não alterar estado de replay ou de negócio para mensagens não autenticadas. Falhas criptográficas terão resposta externa genérica ou descarte, sem expor detalhes úteis a oráculos; o diagnóstico local pode indicar a categoria sem revelar segredos.

### 5.5. Replay, repetição legítima e recursos

- `messageId` aleatório por envelope; validade máxima inicial de 30 segundos e tolerância de relógio configurável, inicialmente dois segundos no localhost. Exigir `0 < expiresAt - issuedAt <= validadeMáxima`, rejeitar emissão futura além da tolerância e expiração anterior ao horário local menos tolerância. O remetente não pode ampliar a janela enviando uma validade maior.
- Cache atômico e limitado de IDs autenticados por remetente, retido até o fim da validade mais tolerância.
- Ao esgotar capacidade, rejeitar novos trabalhos em vez de expulsar IDs ainda válidos e permitir replay.
- Para preservar proteção após reinício sem criar armazenamento persistente de replay, o receptor entra em quarentena de recepção por `validadeMáxima + 2 × tolerância`, inicialmente 34 segundos, medidos por relógio monotônico. As duas margens cobrem emissão adiantada e tolerância de expiração. Após esse intervalo, envelopes anteriores ao reinício já expiraram, assumindo relógio de parede estável dentro da tolerância. Scripts e testes devem esperar o estado `READY`; documentar esse custo operacional. Saltos de relógio fora desse modelo exigem reinicialização controlada, sem alegar proteção irrestrita.
- Repetir o mesmo envelope não pode executar novamente a operação. O domínio pode reconhecer uma duplicata autenticada e reenviar uma resposta previamente armazenada, sem repetir efeitos.
- Usar também `requestId` no domínio para idempotência de comandos que possam ser reenviados com um envelope novo. Associar a entrada ao remetente e ao conteúdo, rejeitando reutilização conflitante.
- Mesmo uma retransmissão não pode reaplicar registro, atualização ou invalidação. Respostas reenviadas podem reutilizar os mesmos bytes já cifrados; isso não é nova cifragem com IV repetido.
- Relógios, expiração, cache de respostas e limite de validade precisam de testes específicos. Proteção contra replay não será alegada se algum desses controles for omitido.

### 5.6. TCP, UDP e superfície pública

- TCP: prefixo de quatro bytes com comprimento do envelope, ordem de rede; leitura completa, detecção de EOF, fragmentação e múltiplos frames. Limite inicial de 1 MiB por envelope, verificado antes de alocar.
- UDP: um envelope por datagrama, limite inicial de **1200 bytes no pacote completo**, não somente no JSON. IDs curtos, payload compacto e notificações de uma alteração por mensagem devem caber nesse orçamento; comprovar com teste usando RSA-3072 e assinatura reais.
- Não fragmentar mensagens UDP na aplicação na primeira versão. Rejeitar payload excedente com erro local claro; não aumentar o limite silenciosamente para caber certificados ou listas.
- Receber em buffer que permita detectar datagramas maiores que o limite; não interpretar pacote truncado como mensagem completa.
- Usar a origem efetiva do datagrama para resposta e associar endpoint de notificação à identidade autenticada; não aceitar endereço de callback arbitrário no payload.
- Todos os comandos de domínio, respostas, erros autenticados, notificações e ACKs passam pelos mesmos adaptadores. Não haverá caminho de fallback em texto claro.
- API conceitual: `seal(project, recipient, payload)`, `open(expectedProject, bytes)`, `SecureTcpChannel` e `SecureUdpEndpoint`; devolução inclui remetente autenticado e informação de duplicata.
- Biblioteca sem conhecimento de DNS, calculadoras, topologia, arquivos ou regiões. Tipos e permissões de domínio continuam em cada aplicação.

## 6. Projeto `mini-dns`

### Componentes e dados

- Um servidor UDP multithread, três clientes requisitantes persistentes e um cliente registrador separado.
- Inicializar exatamente `servidor1 → 192.168.0.10`, `servidor2 → 192.168.0.20`, seguindo até `servidor10 → 192.168.0.100`.
- Guardar tabela de nomes, versão por binding e assinantes concorrentes. Endereços são dados simulados, não destinos para abrir conexão.
- Clientes usam o mesmo socket UDP para consulta e recepção de notificações, com thread de recepção e correlação das respostas.

### Protocolo e comportamento

1. Cliente autenticado executa `SUBSCRIBE`; servidor vincula identidade e endpoint observado. Renovação periódica mantém uma inscrição com prazo limitado.
2. `RESOLVE(name, requestId)` retorna `RESOLVED(name, address, version)` ou erro de nome inexistente.
3. Registrador executa `UPDATE` individual para `servidor1`, `servidor4` e `servidor9`; novos endereços vêm dos comandos/configuração do cenário.
4. Servidor autentica e autoriza o registrador, valida nome e IPv4, atualiza binding e incrementa a versão atomicamente.
5. Servidor envia `BINDING_CHANGED` protegido para cada um dos três clientes; clientes exibem a mudança e atualizam sua visão local somente se a versão for mais nova.
6. Clientes enviam ACK; servidor faz até três tentativas por notificação com timeout e informa clientes que não confirmaram, sem bloquear o socket receptor.
7. Pedidos de consulta e registro também têm correlação e tentativas limitadas. Repetição da atualização não incrementa versão novamente.

Aplicar tamanho máximo de nome, validação estrita dos dez nomes suportados e parsing IPv4 sem resolução DNS externa. Tratar nome inexistente, cliente não inscrito, timeout, registrador não autorizado, pacotes duplicados e notificações fora de ordem.

**Testes essenciais:** mapa completo; três clientes; nove entregas de atualização — três nomes para três clientes; consulta posterior confirma novo valor; perda simulada de ACK; duplicatas; usuário comum tentando atualizar; nome/IP inválido; tamanho do envelope UDP.

## 7. Projeto `service-discovery`

### Componentes e interpretação do enunciado

- Um diretório TCP, três servidores de calculadora TCP e três clientes em processos separados.
- Cada calculadora oferece **todas** as operações: soma, subtração, multiplicação e divisão.
- Tratar as operações como serviços anunciados, por exemplo `calculator.add` e `calculator.divide`; cada serviço possui três instâncias. Assim, demonstrar dois serviços não exige inventar uma aplicação extra.
- Cada servidor terá identificador/nome e endereço descritivo simulado, além do endpoint TCP real em localhost. O cliente conecta ao endpoint real retornado, não a um IP fictício inalcançável.

### Fluxos

1. Calculadora envia `REGISTER(serverId, services, endpoint)` ao diretório; identidade autenticada deve corresponder ao servidor registrado e ao endpoint permitido na configuração local.
2. Heartbeat inicial a cada dois segundos; lease inicial de seis segundos, ambos configuráveis. Expiração usa relógio monotônico local desde a última mensagem recebida, não timestamp fornecido pelo servidor.
3. Cliente pede `DISCOVER(service)`; o diretório remove logicamente expirados e escolhe uma instância ativa por **round robin**, com cursor por serviço e atualização atômica.
4. Resposta inclui identidade, endpoint real e informação descritiva. O cliente já possui a chave pública confiável da calculadora e valida a identidade na resposta à operação.
5. Cliente abre comunicação protegida direta com a calculadora e envia `CALCULATE(operation, a, b, requestId)`.
6. Em falha de conexão, faz nova descoberta com tentativas limitadas. Não entrar em loop nem afirmar que heartbeat elimina a corrida entre descoberta e falha do servidor.

Usar `BigDecimal` com precisão e arredondamento documentados para divisão não exata, por exemplo `MathContext.DECIMAL64`. Rejeitar argumentos não numéricos, operações desconhecidas, divisão por zero e payloads excessivos. Não aceitar `NaN` ou infinito.

**Testes essenciais:** quatro operações nos três servidores; soma e divisão pelos três clientes; seleção `calc-1`, `calc-2`, `calc-3`, `calc-1`; concorrência do cursor; expiração de servidor; nenhum serviço disponível; registro de identidade indevida; erro de conexão após descoberta; divisão por zero.

## 8. Projeto `p2p-naming`

### Topologia e armazenamento

- Seis JVMs independentes: P0, P1, P2, P3, P4 e P5. Identificador numérico correspondente a 0–5.
- Anel fixo, sentido horário: `P0 → P1 → P2 → P3 → P4 → P5 → P0`.
- Cada nó conhece predecessor e sucessor. Configuração local estática pode conter os endpoints e identidades dos seis nós para permitir resposta direta à origem; não existe serviço central em execução nem tabela central de localização de arquivos.
- Armazenar nomes em memória: P0 arquivos 1–10, P1 11–20, P2 21–30, P3 31–40, P4 41–50 e P5 51–60.
- Um servidor TCP com atendimento multithread e uma CLI por nó. Encaminhamentos não devem prender indefinidamente a thread que recebeu a mensagem.

### Busca

1. Validar localmente o padrão `arquivo([1-9][0-9]*)\.ext` e intervalo 1–60, inclusive contra números grandes demais para o parser.
2. Em entrada inválida, imprimir exatamente: **`Erro na entrada de dados. Tente outra vez!`** Não enviar mensagem de busca.
3. Se o arquivo é local, responder na própria CLI sem circular no anel.
4. Caso contrário, enviar `SEARCH(requestId, originId, fileName, path, hopsRemaining)` ao sucessor.
5. Cada nó verifica armazenamento local; se não possuir, adiciona seu ID ao caminho e encaminha somente ao sucessor. Não calcular o dono e pular os intermediários.
6. Nó responsável envia `FOUND(requestId, fileName, ownerId, path)` diretamente à origem, usando a configuração confiável para seu endpoint.
7. Limitar a seis visitas distintas, rejeitar caminho repetido e expirar buscas pendentes. Se o anel completar uma volta sem encontrar, retornar `NOT_FOUND` controlado.
8. Validar também mensagens recebidas pela rede, ainda que a CLI normalmente barre entradas inválidas. Em busca, autenticar o salto anterior; resposta direta deve vir de um nó conhecido e ser correlacionada.

Proteção é **por salto**: nó legítimo abre o pedido e cria envelope novo para seu sucessor. Não prometer sigilo ponta a ponta contra os nós intermediários.

### Logs e testes

Console e arquivo `logs/Pn.log` devem conter timestamp, nó, direção, identidade do par, tipo, `requestId`, arquivo e caminho. Não registrar material secreto. No caso obrigatório, P0 registra envio/recebimento, P1 e P2 registram recepção/encaminhamento e P3 registra recepção/resposta.

**Testes essenciais:** P0 buscando `arquivo35.ext` percorre P0/P1/P2/P3; P1 rejeita `arquivo99.ext`; P4 rejeita `arquivoABC.ext`; nenhum pacote de busca nesses erros; localizar cada um dos sessenta nomes; busca local; consultas concorrentes; nó indisponível; timeout; limite de saltos; ausência simulada de arquivo válido.

## 9. Projeto `cdn`

### 9.1. Componentes

- **Origem TCP:** gera e mantém `arquivo1.ext` a `arquivo1000.ext` no disco, em diretório próprio. Gerador não sobrescreve conteúdo já alterado, salvo comando explícito de reset do cenário.
- **Três edges TCP:** cada um com cache em memória de no máximo cem arquivos, TTL padrão de dez segundos e expulsão LRU.
- **Router TCP:** permitido pelo enunciado; escolhido para evitar um segundo protocolo UDP desnecessário. Recebe arquivo/região fictícia e devolve identidade e endpoint do edge.
- **Cliente:** consulta router, valida destino na configuração confiável e busca conteúdo diretamente no edge.
- **Administração:** comando na CLI local da origem para modificar arquivo e iniciar invalidação. Se futuramente virar cliente remoto, também deverá usar `security` e autorização própria.

Configurar três regiões fictícias, por exemplo norte, centro e sul, com um edge por região. Região desconhecida gera erro claro ou fallback explicitamente configurado, nunca seleção silenciosa. Roteamento geográfico não será apresentado como medição de geolocalização real.

### 9.2. Conteúdo e cache

- Requisição lógica `GET(fileName, requestId)` e resposta com status, `HIT/MISS`, versão, tamanho original em bytes e conteúdo. Usar JSON cifrado, não HTTP em texto claro.
- Gerar arquivos pequenos e determinísticos, por exemplo 4 KiB cada. Limite inicial de arquivo: 256 KiB, compatível com frame de até 1 MiB após serialização e envelope; arquivos maiores ficam fora do escopo inicial.
- Aceitar apenas nomes canônicos `arquivo1.ext` a `arquivo1000.ext`; impedir `../`, caminhos absolutos e fuga do diretório base. Gerador não cria links simbólicos; leitura valida confinamento do caminho real.
- Entrada de cache contém conteúdo, versão e instante monotônico de expiração.
- HIT válido retorna sem abrir consulta de conteúdo à origem. MISS consulta origem via TCP protegido, armazena e responde.
- TTL é verificado antes de servir; não será renovado indefinidamente por HIT.
- `LinkedHashMap` em ordem de acesso com sincronização, ou estrutura equivalente que garanta LRU e limite exato de cem. Não fazer I/O de rede segurando o lock global do cache.
- Coordenar MISS concorrente por arquivo para evitar buscas redundantes, sem bloquear pedidos de outros arquivos.
- Métricas por edge: hits, misses, expirações, expulsões, consultas à origem e invalidações. Tempo ponta a ponta no cliente com relógio monotônico.
- Para deixar a diferença HIT/MISS visível no localhost, permitir latência artificial configurável na origem, por exemplo 100 ms. Identificar claramente como latência simulada; não usá-la para mascarar correção.

### 9.3. Invalidação ativa e consistência

**Problema a evitar:** alterar a origem e apenas disparar uma notificação assíncrona não garante consistência estrita. Um edge pode continuar servindo a versão antiga; um MISS já em andamento pode repovoar o cache depois da invalidação.

Para oferecer consistência forte no cenário acadêmico configurado, implementar atualização serializada por arquivo com uma barreira nos três edges conhecidos:

1. Cada edge mantém canal TCP protegido de controle com a origem; esse canal é independente das consultas de conteúdo para evitar bloqueio circular.
2. Origem recebe a alteração local e prepara a versão nova, ainda sem publicá-la. Mantém a versão antiga acessível para consultas já iniciadas enquanto prepara a barreira.
3. Origem envia `INVALIDATE_PREPARE(file, updateId, nextVersion)` aos três edges. Cada edge bloqueia novos GETs daquele arquivo, deixa leituras/buscas anteriores terminarem, remove o cache e confirma `PREPARED`. Não bloquear consultas de outros arquivos.
4. Depois dos três ACKs, não há leitor antigo ativo no conjunto configurado. A origem publica atomicamente o arquivo e a versão novos; esse é o ponto de efetivação da atualização.
5. Origem envia `INVALIDATE_COMMIT` por TCP. Cada edge mantém o arquivo fora do cache, registra a versão mínima aceita, libera os GETs e confirma. A próxima consulta efetiva MISS e recupera a versão nova.
6. Origem só informa atualização concluída depois das confirmações finais. Mensagens repetidas são idempotentes por `updateId`; versão/generation impede reinserção antiga.
7. Antes da publicação, falha na preparação permite abortar e liberar os edges preparados. Depois da publicação, não voltar à versão antiga: edges sem confirmação permanecem bloqueados até sincronizar com a origem.
8. Na desconexão do canal de controle, o edge falha de forma fechada: não serve cache potencialmente obsoleto até ressincronizar. No início/reconexão, limpar cache e confirmar estado antes de aceitar clientes.

A membresia é fixa nos três edges do cenário; todos precisam estar sincronizados para uma atualização bem-sucedida. Não inventar remoção automática de membro para contornar a barreira. Em falha da origem durante uma atualização, exigir recuperação/reinício controlado e ressincronização, sem alegar recuperação distribuída transparente.

Esse desenho troca disponibilidade por consistência e não implementa consenso, tolerância a partições ou CDN de produção. Se a barreira for simplificada durante a implementação, documentar a garantia mais fraca; não chamar notificação assíncrona de consistência estrita. Locks de leitura por arquivo devem abranger a entrega da resposta; confirmar preparação apenas após terminar leituras e preenchimentos em andamento.

### 9.4. Testes essenciais

- `arquivo20.ext`: primeira consulta MISS, segunda HIT, conteúdo igual e somente uma consulta de conteúdo à origem.
- Tempo de HIT menor no cenário com latência simulada; a prova principal é a contagem de acesso à origem, não uma asserção temporal frágil.
- TTL de dez segundos na demonstração e relógio controlado nos testes: antes do limite HIT; no limite/depois, MISS com leitura atual.
- `arquivo30.ext` carregado nos três edges; modificar origem, aguardar conclusão da barreira e confirmar remoção nos três. Próximo GET em cada edge retorna MISS e versão nova.
- GET simultâneo à invalidação; MISS em andamento; mensagens de controle duplicadas; edge desconectado; proibição de servir cache até ressincronizar.
- Inserir 101 arquivos, verificar expulsão LRU e tamanho máximo cem; testar concorrência de preenchimento.
- Arquivo inexistente, caminho malicioso, região inválida, origem indisponível, frame excessivo e invalidação enviada por identidade não autorizada.

## 10. Execução, configuração e observabilidade

### Portas sugeridas

| Projeto | Processo | Transporte e porta |
| --- | --- | --- |
| Mini-DNS | Servidor | UDP 5300 |
| Mini-DNS | Clientes/registrador | UDP efêmero, mantido durante a execução |
| Descoberta | Diretório | TCP 6000 |
| Descoberta | Calculadoras 1–3 | TCP 6101–6103 |
| P2P | P0–P5 | TCP 7000–7005 |
| CDN | Origem | TCP 8000 |
| CDN | Edges 1–3 | TCP 8001–8003 |
| CDN | Router | TCP 5353 |

Usar `127.0.0.1` por padrão, não todas as interfaces. Hosts, portas, diretórios e tempos serão configuráveis por módulo. Testes automatizados usarão portas efêmeras e sinalização de prontidão, não portas fixas nem sleeps arbitrários.

Cada processo terá configuração para identidade, chaves privadas, manifesto público, endpoint de escuta e pares permitidos. Não aceitar identidade diferente da esperada só porque a mensagem foi assinada por algum participante conhecido.

Exemplos de interface a implementar, ainda não disponíveis:

```bash
./gradlew :mini-dns:run --args='server --config ...'
./gradlew :mini-dns:run --args='client --id dns-client-1 --config ...'
./gradlew :mini-dns:run --args='registrar --config ...'
./gradlew :service-discovery:run --args='directory --config ...'
./gradlew :service-discovery:run --args='server --id calc-1 --config ...'
./gradlew :service-discovery:run --args='client --id client-1 --config ...'
./gradlew :p2p-naming:run --args='node --id P0 --config ...'
./gradlew :cdn:run --args='origin --config ...'
./gradlew :cdn:run --args='edge --id edge-1 --config ...'
./gradlew :cdn:run --args='router --config ...'
./gradlew :cdn:run --args='client --config ...'
```

- Configurar encaminhamento de stdin nas tarefas interativas. Para vários processos, preferir distribuição `installDist` e executáveis gerados, evitando depender de dezenas de builds Gradle simultâneos.
- Um script de preparação por projeto gera/configura identidades usando a CLI de segurança e espera prontidão, inclusive a janela de reinício antirreplay.
- Scripts opcionais de demonstração devem iniciar JVMs distintas, registrar seus próprios PIDs e encerrar somente esses processos. Nada de encerramento amplo por nome de processo.
- Mensagens de console em português, incluindo erros de uso. Erros esperados não encerram o servidor nem produzem stack traces intermináveis.
- Timeouts de conexão/leitura, filas limitadas, limite de clientes/pendências e encerramento de sockets/executores são obrigatórios.
- Não compartilhar instâncias mutáveis de `Cipher` ou `Signature` entre threads.
- Evidências locais podem mostrar nomes e resultados após decifragem; nunca chaves. Captura de rede para a apresentação deve mostrar a ausência desses payloads em texto claro, sem alegar que isso, sozinho, prova segurança.

## 11. Estratégia de testes e validação

### Camadas

1. **Unitários:** regras de domínio, parsers, round robin, faixas de arquivos, TTL/LRU, serialização, parâmetros criptográficos e autorização.
2. **Integração de transporte:** TCP e UDP reais em loopback com o mesmo envelope utilizado pelas aplicações.
3. **Integração de cada projeto:** componentes comunicando-se de verdade, erros de rede e concorrência.
4. **Smoke multiprocesso:** JVMs separadas nos cenários exigidos, incluindo três clientes DNS, três calculadoras/três clientes, seis nós P2P e a CDN completa.
5. **Ensaio manual:** comandos individuais e explicação dos resultados, seguindo o roteiro de avaliação.

### Segurança — lista mínima

- Ida e volta com AES-GCM, OAEP e PSS configurados explicitamente; conteúdo cifrado diferente em envios distintos do mesmo payload.
- Chave AES nova por envelope; abertura apenas pelo destinatário; assinatura apenas pelo remetente configurado.
- Alteração de cabeçalho, chave protegida, IV, ciphertext, tag e assinatura; rejeitar sem alterar estado de negócio.
- Chave pública desconhecida/substituída, projeto incorreto, destinatário errado e identidade divergente do endpoint esperado.
- Expiração, timestamp futuro, replay concorrente, capacidade do cache antirreplay, reinício/quarentena e idempotência de negócio.
- Repetição legítima de resposta/ACK, limites UDP com pacote completo e perda/reordenação de datagramas.
- Frame TCP negativo/excessivo, bytes truncados, mensagens concatenadas, EOF no meio e payload JSON inválido depois de autenticação válida.
- Nenhum tráfego de domínio em texto claro, inclusive heartbeats, ACKs e invalidações. Sem modo inseguro usado pelos roteiros de apresentação.

Configurar `./gradlew check` para agregar verificações dos cinco módulos; isso não acontece automaticamente apenas pelo plugin `base` atual. Se houver tarefa `integrationTest`, conectá-la explicitamente a `check` ou documentar o comando obrigatório separado. Injetar relógios, coordenar testes com sinais/latches e usar diretórios temporários apenas na implementação.

## 12. Etapas de implementação e pontos de controle

### Etapa 1 — Base Gradle e contrato de segurança

- Habilitar módulos e dependências sem acoplamento entre aplicações.
- Definir toolchain 21, versões, testes, agregação e tarefas de execução.
- Implementar geração de identidades, manifestos, envelope, proteção, replay e adaptadores TCP/UDP.
- Validar pacote UDP de 1200 bytes e round trip TCP com chaves RSA reais antes de desenvolver protocolos de negócio.
- **Saída verificável:** `:security:test` passa; duas JVMs trocam mensagens protegidas por TCP e UDP; adulteração/replay são rejeitados.

### Etapa 2 — Mini-DNS e descoberta de serviços

- Implementar Mini-DNS completo, incluindo assinatura/inscrição, registrador, versões, notificações e ACKs.
- Implementar diretório, calculadoras, clientes, leases e round robin.
- **Saída verificável:** DNS com três clientes recebendo três mudanças; dois serviços descobertos e executados; balanceamento e falha demonstrados.

### Etapa 3 — P2P e CDN

- Implementar anel, validação local, encaminhamento, resposta direta e logs persistidos.
- Implementar origem/gerador, router, edges, LRU/TTL, métricas e canal de controle.
- Implementar invalidação com barreira por arquivo, ACKs, versão e comportamento fechado na falha.
- **Saída verificável:** três casos obrigatórios do P2P e os três cenários de cache do PDF reproduzíveis.

### Etapa 4 — Integração, documentação e entrega

- Testes de segurança sobre cada enlace, cenários de concorrência e falha; varrer envio direto que contorne `security`.
- READMEs por módulo com comandos exatos, ordem de inicialização, erros tratados e limitações.
- Atualizar README raiz com os cinco módulos e explicação de que somente segurança é compartilhada.
- Documentar parâmetros criptográficos, confiança inicial, ausência de forward secrecy e consistência da CDN.
- Ensaiar vídeo, gerar pacote sem segredos e verificar execução em diretório limpo.
- **Saída verificável:** build/testes aprovados e demonstração executável sem ajustes manuais no código.

### Distribuição temporal sugerida

| Data | Meta |
| --- | --- |
| 17/10 | Contratos, build e núcleo de segurança validado |
| 18/10 | Mini-DNS, descoberta e P2P; início da CDN |
| 19/10 | CDN completa, invalidação e testes integrados |
| 20/10 | Correções, documentação, ensaio, vídeo e envio com antecedência |

Prazo apertado: após estabilizar a API de `security`, a dupla pode dividir Mini-DNS/descoberta e P2P/CDN. Definir responsáveis em conjunto; não atribuir autoria de implementação automaticamente. Priorizar requisitos obrigatórios e compreensão do código, não funcionalidades adicionais. Não cortar autenticação ou enviar controle em texto claro para ganhar tempo.

## 13. Documentação e apresentação

Arquivos previstos, a criar somente na fase de implementação:

- `docs/plano-implementacao.md`: cópia deste plano.
- `docs/seguranca.md`: perfil criptográfico, formato, chaves, ameaças, replay e limitações.
- `docs/roteiro-apresentacao.md`: comandos, sequência e evidências esperadas.
- `modules/<projeto>/README.md`: componentes, configuração, portas, execução, testes, exceções e limitações.
- Configurações de exemplo, scripts de preparação e gerador de arquivos; segredos, caches e logs de execução ignorados pelo Git.

Distribuição sugerida dos oito minutos: 30 s de arquitetura/tecnologias; 60 s de RSA/AES e confiança; 60 s de Mini-DNS; 60 s de descoberta; 60 s de P2P; 100 s de CDN; 80 s de organização do código, exceções e limitações; 30 s de conclusão. Total: oito minutos; ensaiar abaixo desse limite.

Na demonstração, executar uma operação por vez. Mostrar ao menos uma entrada incorreta, explicar as exceções tratadas, indicar onde threads/sockets aparecem e abrir o código que implementa os requisitos. A explicação deve deixar claro o que cada autor compreende e implementou, respeitando o alerta do PDF sobre código sem a devida explicação.

Pacote final: pasta com nome no padrão solicitado, como `seu-nome-pratica-off1`, ajustado à orientação para dupla; fontes, wrapper, documentação e comandos para preparar/compilar/executar. Confirmar no SIGAA como entregar/referenciar o vídeo e qual identificação usar na pasta da dupla. Não incluir `.gradle`, builds desnecessários, configurações da IDE ou chaves privadas. A natureza offline da prática não implica automaticamente build sem internet; se isso for exigido, preparar dependências/distribuições com antecedência e confirmar a regra.

## 14. Riscos e pontos de atenção

- **Aceitação pela disciplina de Segurança:** o usuário escolheu híbrida explícita; os parâmetros detalhados são recomendação técnica. Validar com o professor se há exigência adicional de tamanho de chave, gestão de certificados ou roteiro específico, sem bloquear o planejamento atual.
- **Protocolo próprio:** não alegar certificação NIST, equivalência a TLS ou segurança de produção apenas por usar primitivas padronizadas.
- **UDP:** RSA e assinatura ampliam o pacote; o orçamento de 1200 bytes é um teste de arquitetura obrigatório, não um detalhe para o fim.
- **Chaves locais:** a demonstração confia no provisionamento local; separar fingerprints públicos de material privado e explicar o limite do mesmo usuário do sistema operacional.
- **Replay/reinício:** a quarentena é parte da proteção planejada e aumenta o tempo de inicialização. Não removê-la sem persistência ou outro mecanismo equivalente de frescor autenticado.
- **CDN:** barreira forte exige conectividade dos membros; não esconder indisponibilidade nem substituir por invalidação assíncrona mantendo a mesma alegação.
- **Prazo:** quatro aplicações mais segurança em poucos dias exigem escopo fechado; GUI, protocolos de sessão, eleição de líder, topologia dinâmica, replicação de diretório e tolerância a partições estão fora da primeira versão.
- **Ambiente:** Gradle ainda não executado, dependências ainda não selecionadas e ocupação das portas ainda não verificada. Validar no início da implementação.
- **Repositório:** preservar arquivos não rastreados e atualizar este plano se decisões mudarem; exemplos de comandos acima não são funcionalidades já existentes.

## 15. Referências técnicas consultadas

Consultadas em 17/10/2026. Sustentam escolhas de primitivas e parâmetros; não validam o protocolo completo proposto.

1. Enunciado local: `docs/pratica-offline-1-2026-2.pdf` e `README.md`.
2. OWASP — Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html — AES, modos autenticados, RSA/OAEP, aleatoriedade e gestão de chaves; a página trata principalmente armazenamento e foi usada para princípios criptográficos, não como especificação de transporte.
3. NIST SP 800-38D: https://csrc.nist.gov/pubs/sp/800/38/d/final — GCM e autenticação; publicação com revisão anunciada, usar tag de 128 bits e respeitar unicidade de IV.
4. NIST SP 800-56B Rev. 2: https://csrc.nist.gov/pubs/sp/800/56/b/r2/final — estabelecimento/transporte de chaves com RSA; página registra reafirmação como atual em janeiro de 2026.
5. Java 21 — `OAEPParameterSpec`: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/OAEPParameterSpec.html — especificar digest e MGF, sem defaults históricos SHA-1.
6. Java 21 — `PSSParameterSpec`: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/PSSParameterSpec.html — parâmetros explícitos de assinatura PSS.
7. Java 21 — `Cipher`: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html — AAD, tag e exigência de IV diferente a cada cifragem GCM com uma mesma chave.
