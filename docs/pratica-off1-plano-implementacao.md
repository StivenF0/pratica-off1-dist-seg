# Plano integrado — Sistemas Distribuídos e Segurança Computacional

## 1. Objetivo e fontes

Implementar os quatro exercícios como aplicações Java 21 de terminal, com processos independentes e apenas a segurança compartilhada. O escopo é uma demonstração de graduação em localhost, com código explicável, sockets e threads reais; não uma plataforma de produção.

Fontes, lidas em conjunto em 17/10/2026:

- **SD:** `docs/pratica-offline-1-2026-2.pdf`, páginas 2–6: requisitos funcionais, quantidades, cache e testes; página 7: apresentação.
- **SEG:** `docs/pratica-offline-1-seg-2026-2.pdf`, páginas 2–7: processos, handshake RSA/AES, HMAC, logs e casos negativos; página 8: apresentação.
- `README.md`, configuração Gradle, código e testes existentes de `modules/security`.

Aplicar a **união dos requisitos**. O silêncio de um PDF não elimina uma exigência do outro. Quando um caso de teste é mais específico que a arquitetura genérica, demonstrar o caso específico: por exemplo, o Router/GeoDNS usará UDP, embora a descrição geral permita TCP.

Autores: Stiven Felipe e Robert Luann. Entrega indicada nos dois PDFs: **20/10/2026 até 23h59**, pelo SIGAA; vídeo de até **8 minutos**.

Esta versão foi salva em `/home/robert/.opencode/plan/pratica-off1-plano-integrado.md` por restrição do modo de planejamento. Após trocar para um agente com escrita no repositório, substituir o conteúdo de `docs/pratica-off1-plano-implementacao.md` por esta revisão. Nenhum código foi alterado por este documento.

## 2. Correções em relação ao plano anterior

| Ponto | Requisito confirmado | Decisão deste plano |
| --- | --- | --- |
| Integridade/autenticidade das mensagens | SEG exige HMAC, inclusive testes de HMAC corrompido e hash sem chave | Implementar **HMAC-SHA-256 com chave separada**; GCM e PSS não substituem esse requisito |
| Troca de chaves | SEG pede handshake inicial e sessões AES/HMAC | RSA transporta as chaves no início da sessão; não executar RSA em cada mensagem de aplicação |
| Identidade dos participantes | HMAC prova posse do segredo, não vincula sozinho uma chave a um nome | Preservar chaves públicas confiáveis e usar a assinatura PSS já implementada **no handshake**, não em cada mensagem |
| Mini-DNS | SD pede mudanças em `servidor1`, `servidor4` e `servidor9`; SEG fixa `servidor1 → 192.168.0.111` | Demonstrar as três alterações e o valor exato de `servidor1` |
| Notificações DNS | Caso de SEG é denominado broadcast/multicast | Demonstrar multicast UDP real; não chamar três unicasts de multicast |
| Descoberta | SEG pede lista de servidores ativos cifrada e chamadas balanceadas | Devolver a lista completa ordenada por round robin; o cliente usa o primeiro endereço |
| GeoDNS | SEG, página 7, pede consulta via UDP cifrado | Router UDP, demais enlaces de conteúdo da CDN em TCP |
| P2P inválido | SEG exige rejeição antes de criptografar ou abrir conexão para a busca | Validar na CLI antes de iniciar aquela busca, preservando o listener já em execução |
| CDN inválida | SEG exige não consultar a origem e encerrar conexão com HMAC inválido | Validar no Edge; testar ausência de acesso à origem e ausência de alteração do cache |
| Cache | SD fixa cem arquivos por Edge e mil na origem | Manter esses limites, mesmo que SEG não repita a capacidade do cache |

A proposta anterior de uma versão sem autenticação não é adotada. A versão atual do código também não está completa para SEG: não possui HMAC nem handshake de sessão.

## 3. Arquitetura mínima e estado atual

```text
modules/
  security/           chaves, handshake, AES/HMAC e transporte seguro
  mini-dns/           DNS UDP, registrador e três clientes
  service-discovery/  diretório, três calculadoras e três clientes
  p2p-naming/         seis nós TCP em anel
  cdn/                origem, três Edges, GeoDNS UDP e cliente
```

- Cada aplicação depende apenas de `security`, sem dependências entre os quatro exercícios.
- `security` é biblioteca carregada em cada processo, não um servidor central.
- Uma classe de entrada por módulo, com papéis por argumento e classes concretas conforme necessário. Sem camadas controller/service/repository, interfaces sem necessidade ou módulo `common`.
- JCA/JCE, sockets, coleções, arquivos e executores do JDK. Não adicionar dependências de produção inicialmente.
- Mensagens curtas de comando em UTF-8, com quantidade e tamanho de campos validados. Conteúdo de arquivos usa bytes com comprimento explícito; não separar conteúdo arbitrário com `split` nem usar desserialização Java de objetos recebidos da rede.
- Pequenos executores para conexões concorrentes; recepção UDP com tratamento por pacote. Estado compartilhado sincronizado; I/O de rede fora do lock da tabela/cache.
- Configuração local simples: identidade, chaves, pares permitidos, hosts e portas. CLI e logs em português.

Estado observado:

| Área | Já existe | Falta |
| --- | --- | --- |
| Build | Gradle 9.8.1, Java 21, JUnit, `check` ligado a `security` | Builds/dependências dos quatro projetos e habilitação de P2P/CDN |
| Criptografia | RSA-3072/OAEP-SHA-256, AES-256-GCM e assinatura RSA-PSS por envelope | HMAC, duas chaves de sessão e handshake inicial |
| Confiança | Pares RSA separados, arquivos PEM, manifestos e validação de fingerprints | Reutilizar no handshake, sem criar PKI ou nova infraestrutura |
| Replay | Controle em memória, expiração atômica e quarentena inicial | Aplicar ao handshake e acrescentar sequência nas mensagens da sessão |
| Transporte | Frames TCP limitados e datagramas de até 1200 bytes | Integrar sessões, HMAC e regras de descarte/fechamento |
| Testes | Relatórios anteriores: 15 testes sem falhas, inclusive duas JVMs | Novos testes de HMAC/sessão e todos os cenários dos exercícios |
| Domínio | Quatro diretórios com `.gitkeep` | Implementar os quatro exercícios |

Os testes existentes não foram reexecutados durante este planejamento. O PDF de Segurança recém-adicionado e as alterações já presentes no repositório devem ser preservados.

## 4. Segurança compartilhada

### 4.1. Perfil fixo

| Finalidade | Escolha |
| --- | --- |
| Transporte das chaves | RSA-3072, expoente 65537, OAEP com SHA-256 e MGF1/SHA-256 explícitos |
| Chave de dados | AES de **256 bits**, nova por sessão |
| Cifra dos dados | `AES/GCM/NoPadding`, tag de 128 bits, mantendo a implementação do JDK já utilizada |
| Integridade exigida por SEG | `HmacSHA256`, chave aleatória de 256 bits **independente** da chave AES; MAC completo de 32 bytes |
| Autenticidade de identidade | RSA-PSS/SHA-256 já existente na abertura da sessão; chave pública previamente fixada à identidade |
| Aleatoriedade | `SecureRandom`, `KeyGenerator` e `KeyPairGenerator` |

OAEP já é um padding RSA. Não trocar para RSA sem padding ou PKCS#1 v1.5 apenas para reduzir linhas. Não trocar AES-GCM por ECB nem usar SHA-256 sem chave como substituto de HMAC.

GCM já oferece autenticação de dados, mas o **HMAC explícito é necessário para cumprir os testes de SEG**. Mantê-lo junto de GCM evita reescrever a cifra atual e permite demonstrar exatamente a validação pedida. Não usar a mesma chave nos dois algoritmos.

### 4.2. Confiança e autenticidade

- Reutilizar `LocalIdentity`, `KeyFiles`, `TrustStore` e a CLI existentes. Não refazer o formato do manifesto nesta etapa.
- Chaves públicas são provisionadas por arquivos locais confiáveis. Nenhum participante passa a ser confiável por enviar uma chave na rede.
- Manter pares RSA separados para transporte e assinatura, porque já existem e têm finalidades distintas. PSS será usado no handshake; mensagens normais usarão AES/HMAC da sessão autenticada.
- O iniciador é identificado pela assinatura da oferta de chaves; o destinatário esperado é identificado pela chave RSA pública fixada e pela confirmação válida com as chaves que apenas ele deveria conseguir recuperar.
- HMAC autentica mensagens perante os dois participantes que compartilham o segredo. Não oferece assinatura pública, prova a terceiros ou não repúdio.
- Cada aplicação autoriza operações pelo par autenticado: registrador atualiza DNS, calculadoras registram serviços e origem invalida caches. Um nome no payload ou o endereço IP, isoladamente, não é prova de identidade.
- Manter arquivos privados fora do Git, permissões restritas, recusa de sobrescrita e ausência de segredos nos logs. PKCS#8 não cifrado em repouso continua sendo limitação didática.

### 4.3. Handshake mínimo reutilizável

O canal será híbrido pela combinação **RSA no estabelecimento** e **AES/HMAC nos dados**, como descrito nos casos de SEG. Não é necessário executar RSA em cada comando: as chaves AES/HMAC são transportadas cifradas no handshake. Somente metadados públicos de enquadramento/contexto ficam fora da cifra; nomes consultados, operações, arquivos, conteúdo e erros de domínio ficam cifrados.

1. **Iniciador → receptor: `KEY_EXCHANGE`.** Gerar uma chave AES e uma chave HMAC, cada uma com 32 bytes. Cifrar os 64 bytes com RSA-OAEP do receptor. A oferta inclui projeto, identidades, identificador aleatório da sessão e validade curta, protegidos por PSS. Incluir HMAC da oferta usando a chave HMAC proposta; nenhum segredo vai em claro.
2. **Receptor valida.** Conferir formato, identidade/assinatura, contexto e validade; recuperar as duas chaves; conferir HMAC. Registrar a oferta contra replay atomicamente, somente após a validação criptográfica. Não registrar serviço, atualizar nome ou consultar arquivo durante a negociação.
3. **Receptor → iniciador: `READY`.** Responder com AES-GCM e HMAC da sessão, vinculando o mesmo identificador e as identidades. O iniciador só envia comandos depois de validar essa confirmação. O servidor só entrega dados ao domínio depois de concluir sua validação da oferta.
4. **Falha.** Em TCP, fechar somente a conexão afetada. Em UDP, descartar a oferta/confirmação inválida; o iniciador termina por timeout. Não instalar sessão com chave parcial, assinatura inválida ou HMAC inválido.

O RSA transporta somente material curto de chaves; 64 bytes cabem no OAEP escolhido. A assinatura cobre o cabeçalho canônico, o material RSA cifrado e o HMAC da oferta. A confirmação tem tipo/direção próprios para não aceitar reflexão de uma mensagem enviada pelo próprio cliente.

Reutilizar o controle antirreplay atual **para ofertas de handshake**: prazo máximo de 30 s, tolerância de 2 s e quarentena inicial já implementada de 34 s. Esse mecanismo não é exigido nominalmente pelos PDFs, mas já existe e evita redesenhar a negociação para proteger reinícios. Esperar prontidão uma vez por processo, antes de gerar/oferecer chaves na demonstração; isso não limita a sessão a 30 s.

Uma oferta UDP repetida não pode reinstalar chaves nem zerar contadores. Se a sessão ainda existe, reenviar os mesmos bytes da confirmação já produzida; se não existe, rejeitar e iniciar nova negociação com chaves novas. Limitar ofertas/sessões por participantes configurados e tempo de espera; não criar retries automáticos de comandos de domínio mutáveis.

### 4.4. Mensagens da sessão

```text
cabeçalho: versão, tipo, sessionId, direção, sequência, comprimento
corpo:     ciphertext AES-GCM com tag
final:     HMAC-SHA-256(cabeçalho || ciphertext || tag)
```

- Uma sessão possui as duas chaves, as identidades verificadas e contadores por direção. Não criar um serviço ou repositório genérico de sessões.
- Construir o IV GCM de 96 bits com um prefixo de direção de 32 bits e uma sequência crescente de 64 bits. Direções diferentes usam prefixos diferentes. Nunca repetir sequência com a mesma chave; esgotamento encerra a sessão e exige chaves novas.
- Sincronizar geração de sequência/cifra por sessão; não compartilhar objetos mutáveis `Cipher` ou `Mac` entre threads.
- Autenticar o cabeçalho como AAD do GCM e como parte do HMAC. Comparar MACs com `MessageDigest.isEqual` e só decifrar após HMAC válido.
- Antes de entregar bytes, verificar tag GCM, sessão, direção e replay. Usar janela fixa pequena de sequências recebidas para aceitar reordenação UDP sem reaplicar pacotes; atualizar a janela atomicamente após validação.
- Após reinício, descartar sessões AES/HMAC; nunca persistir essas chaves e reiniciar seus contadores. O handshake gera material novo e o guard de ofertas impede reinstalação de material antigo por replay dentro do modelo de relógio documentado.
- Uma sessão TCP dura até o fechamento da conexão. Uma associação UDP dura durante a execução do cenário; reconexão não reutiliza contadores/chaves. Sem renovação automática, negociação de algoritmos ou rotação em segundo plano.

### 4.5. Transporte, erros e logs

- TCP mantém prefixo de comprimento de quatro bytes, limite de 1 MiB, leitura completa, EOF e timeout de handshake/requisição. Conexões de registro/controle intencionalmente persistentes não expiram apenas porque ficaram ociosas.
- UDP mantém limite de 1200 bytes no pacote completo e detecção de truncamento. Ofertas RSA/PSS e multicast agregado precisam passar por teste de tamanho real. Sem fragmentação de aplicação.
- HMAC inválido ou cifra inválida nunca alcança código de domínio. Não calcular, encaminhar busca, consultar origem nem alterar tabelas antes da validação.
- UDP inválido: descartar e registrar falha, continuando o listener. TCP inválido: registrar e fechar aquela conexão, não o servidor. Na CDN, preservar integralmente o cache.
- Entrada de domínio inválida em canal válido: devolver/imprimir **`Erro na entrada de dados. Tente outra vez!`**. Não responder a pacote não autenticado com detalhes de RSA, padding ou HMAC.
- Logs de ambos os participantes: horário, processo, par, sessionId abreviado, direção, tipo e resultado `HMAC_OK`/`HMAC_FAIL`. Não registrar chaves, material decifrado de handshake nem HMAC completo. Nunca imprimir `HMAC_OK` sem ter calculado e comparado o MAC.
- Distinguir falha de assinatura/contexto na oferta de falha de HMAC em sessão. Os testes de HMAC da negociação devem adulterar a confirmação protegida, e não apenas produzir uma falha de assinatura.

### 4.6. Alcance da mudança em `security`

1. Reutilizar geração/leitura de chaves, confiança local, OAEP, GCM, PSS e enquadramento existentes.
2. Adaptar o envelope assinado para abertura de sessão, sem criar uma segunda implementação dos mesmos algoritmos.
3. Acrescentar um objeto concreto de sessão para AES/HMAC, sequências e autenticação do par. Adaptar os dois transportes a essa sessão.
4. Retirar RSA, PSS, timestamps e UUID por mensagem normal; ficam no estabelecimento. Não manter um modo antigo sem HMAC nem fallback em claro.
5. Atualizar todos os testes, exemplo de uso e CLI/documentação afetados. O formato de rede será uma nova versão; rejeitar formatos antigos em vez de suportar dois protocolos por conveniência.
6. Não apagar chaves privadas/manifestos existentes. A migração do protocolo não exige mudar silenciosamente os pares RSA ou seus fingerprints.

## 5. Mini-DNS — requisitos combinados

Componentes: servidor DNS UDP, clientes C1/C2/C3 e registrador, todos em JVMs distintas.

- Mapa inicial: `servidorN → 192.168.0.(10 × N)`, para N de 1 a 10, exatamente como nos PDFs.
- Cada cliente e o registrador negociam sessões individuais com o DNS. Associar endpoint unicast à origem observada e à identidade autenticada; não aceitar callback arbitrário.
- C1 consulta `servidor1`; resultado inicial `192.168.0.10`, cifrado e com HMAC validado nas duas pontas.
- Manter tabela local nos três clientes. Registrar a participação depois de handshake e consulta válidos; inscrições duram a execução, sem lease ou heartbeat.
- Registrador altera `servidor1 → 192.168.0.111`. Para cobrir SD, alterar também `servidor4 → 192.168.0.144` e `servidor9 → 192.168.0.199`; os dois últimos são valores de demonstração, não números impostos pelo PDF.
- Respostas distinguem consulta de notificação. Clientes imprimem a mudança e atualizam a tabela somente após validação HMAC/GCM.
- C2 consulta `servidor99`: resposta de entrada inválida. Pacote com HMAC corrompido: descarte sem consulta ao mapa e log de falha, mantendo o servidor funcionando.

### Multicast sem nova gestão de chave de grupo

Usar multicast UDP real para notificações, com grupo/porta/interface configurados para a demonstração local. Não substituir silenciosamente por fan-out unicast.

Para preservar sessões e autenticação individual sem criar uma chave de grupo, cada datagrama multicast contém **três registros protegidos**, um por sessão C1/DNS, C2/DNS e C3/DNS. Cada cliente seleciona o registro de seu sessionId e verifica seu próprio HMAC. Não distribuir a chave HMAC de um cliente aos demais.

O contêiner externo só delimita os registros, com contagem/comprimentos limitados; cada registro autentica sessão, sequência e conteúdo. Usar os mesmos contadores da direção DNS → cliente, inclusive para mensagens unicast, evitando IV repetido. Notificar uma alteração por datagrama e testar o agregado abaixo de 1200 bytes.

`shortcut: multicast agregado contempla exatamente os três clientes do exercício; rever empacotamento e gestão de grupo se a quantidade de participantes crescer.`

Configurar a interface multicast explicitamente e testar com três JVMs receptoras. Não depender apenas de mock; se o ambiente bloquear multicast, registrar o impedimento e validar alternativa com o professor, sem marcar esse requisito como concluído.

## 6. Descoberta de serviços

Componentes: diretório TCP, calculadoras S1/S2/S3 e três clientes, todos como processos separados. Cada calculadora implementa soma, subtração, multiplicação e divisão.

1. Cada calculadora negocia sessão com o diretório e envia `REGISTER` cifrado com HMAC. A identidade deve corresponder ao registro e ao endpoint permitido na configuração local.
2. Manter conexão de registro aberta; remover a inscrição correspondente em EOF/erro. Fechamento de uma conexão antiga não pode remover uma inscrição nova da mesma calculadora.
3. Cliente negocia sessão com o diretório e pede um serviço. A resposta contém a **lista completa dos servidores ativos**, identidades e endpoints, cifrada e autenticada.
4. Para manter round robin simples e demonstrar alternância entre clientes, ordenar a lista por ID; o diretório usa um cursor único e devolve essa lista rotacionada, começando pelo próximo servidor. O cliente seleciona o primeiro. Todos os servidores oferecem as mesmas quatro operações; não criar política de balanceamento plugável.
5. Cliente negocia sessão própria com a calculadora selecionada. Demonstrar `10 + 20 → 30` e `5 * 4 → 20`, com logs identificando o servidor escolhido. Demonstrar os três servidores ativos e, em cenário com S1/S2, alternância entre eles.
6. Operação `Calcular modulo` não cadastrada: mensagem de entrada inválida. S3 indisponível ou HMAC inválido na confirmação: rejeitar a chamada, registrar erro e manter os demais processos funcionando. Para testar indisponibilidade após uma descoberta válida, encerrar S3 depois de obter seu endpoint e antes de executar a chamada.

Usar `double`, rejeitando operandos/resultados não finitos, divisão por zero e número excessivo de campos/bytes. Explicar arredondamento de ponto flutuante; não há requisito monetário ou de precisão decimal exata.

`shortcut: disponibilidade é detectada por fechamento/erro da conexão local de registro; adicionar heartbeat apenas se for exigido detectar travamentos silenciosos ou conexões meia-abertas.`

## 7. P2P em anel

- Seis JVMs: P0–P5, IDs 0–5, predecessor e sucessor configurados. Sentido horário fixo.
- Arquivos simulados por strings: P0 1–10, P1 11–20, P2 21–30, P3 31–40, P4 41–50 e P5 51–60.
- TCP multithread; configuração local dos endpoints permitida, sem diretório central nem busca direta pelo dono calculado a partir do número.
- Validar nome canônico e intervalo 1–60 **antes de abrir conexão de saída, negociar chave ou cifrar aquela busca**. O listener do nó permanece funcionando.
- `arquivo99.ext` em P1 e `arquivoABC.ext` em P4 produzem a mensagem exata de erro, sem novos pacotes ou handshake por causa desses comandos.
- Busca válida usa `requestId`, origem, nome e limite de saltos. O caminho é comprovado pelos logs; não precisa ser duplicado no payload.
- Cada salto negocia/usa sua própria sessão RSA/AES/HMAC: P0 → P1 → P2 → P3 para `arquivo35.ext`. P1/P2 abrem, validam HMAC, consultam seus nomes e só então cifram para o sucessor.
- P3 responde diretamente a P0 em sessão própria protegida. Correlacionar a resposta; limitar saltos e tempo de buscas pendentes.
- No caso adulterado P4 → P5, P5 registra `HMAC_FAIL`, descarta/fecha a conexão e **não encaminha para P0**. Outras buscas continuam possíveis.
- Cada nó imprime e armazena log de envio/recebimento e validação criptográfica. A criptografia é salto a salto, não sigilo contra os próprios nós intermediários.

## 8. CDN

### Componentes e cache

- Origem TCP com **mil arquivos reais no disco**, `arquivo1.ext`–`arquivo1000.ext`, gerados com conteúdo pequeno e determinístico. Não sobrescrever conteúdo alterado ao reiniciar o gerador.
- Três Edges TCP; cada um usa também TCP como cliente da origem. Cache em memória com **cem entradas**, FIFO e TTL de dez segundos verificado antes de servir.
- Router/GeoDNS **UDP**, regiões fictícias mapeadas estaticamente aos Edges. Cliente negocia sessão UDP com o Router e sessão TCP distinta com o Edge retornado.
- Sessões protegidas também em Edge → origem e origem → Edge para controle. Nenhum enlace de registro, resposta ou controle fica em claro.
- `GET /arquivo20.ext`: MISS busca na origem via AES/HMAC e guarda bytes; segundo GET é HIT, com nova cifragem/HMAC para o cliente e sem consulta de conteúdo à origem.
- Registrar tempos e contagem de acessos à origem. A demonstração deve mostrar o segundo tempo menor; comparar também acesso à origem para não depender só de uma medição ruidosa. Se localhost não tornar a diferença visível, admitir latência simulada pequena e fixa na origem, explicitamente identificada, sem mudar a lógica de cache.
- Aceitar somente nomes canônicos no intervalo; limitar tamanho de arquivo e frame, por exemplo arquivo até 256 KiB e frame até 1 MiB. Validar confinamento do caminho no diretório de origem e não seguir links para fora dele.
- `GET /arquivoXYZ.ext`: Edge valida depois do HMAC, não consulta a origem nem insere no cache e retorna a mensagem exata de erro.
- HMAC inválido, HMAC ausente ou substituído por SHA-256 sem chave: Edge fecha a conexão do cliente e alerta no log, sem modificar cache ou consultar a origem.
- Não coalescer MISS nem implementar métricas extensas. Sincronizar cache/limite sem segurar seu lock em I/O.

### Invalidação ativa sem coordenação por arquivo

Manter uma barreira global simples porque os PDFs usam a expressão **consistência estrita**. Apenas disparar uma mensagem assíncrona não satisfaz essa garantia sob leituras concorrentes.

1. Atualizações passam exclusivamente pela CLI administrativa da origem; não alterar o arquivo por fora do protocolo. Atualizações são serializadas.
2. Origem envia `INVALIDATE /arquivo30.ext` em canal TCP protegido aos três Edges. Cada Edge entra em manutenção global, rejeita novos GETs temporariamente, espera GETs/MISS anteriores e suas respostas terminarem, remove o arquivo e confirma com HMAC válido.
3. A origem continua servindo a versão antiga para operações já iniciadas durante a preparação. Não manter um lock de arquivo enquanto espera os ACKs dos Edges.
4. Somente após os três ACKs, publicar atomicamente o arquivo novo. Enviar `RESUME` protegido e esperar confirmação antes de anunciar atualização concluída.
5. A próxima consulta de `arquivo30.ext` em cada Edge gera MISS e busca a versão nova. TTL expirado também obriga busca segura e é testado separadamente.
6. Conexão de controle perdida implica Edge indisponível até reinício/sincronização com cache limpo. Se alguma etapa da atualização falhar, não anunciar sucesso nem liberar um Edge cujo estado seja incerto; interromper o cenário e recuperar de forma controlada.

Contador de GETs em andamento, entrada em manutenção e autorização de novos GETs precisam ser coordenados atomicamente. Não há protocolo de recuperação automática, consenso, log transacional distribuído ou garantia de disponibilidade sob partições.

`shortcut: atualizações pausam globalmente os três Edges e falhas exigem recuperação manual; usar coordenação mais fina apenas se disponibilidade contínua se tornar requisito.`

## 9. Matriz dos cenários obrigatórios

| Caso | Fonte | Evidência de conclusão |
| --- | --- | --- |
| Processos separados | SEG p.2; SD p.6 | Componentes em JVMs distintas com sockets reais |
| Sessão híbrida e HMAC | SEG p.3–7 | Handshake RSA, duas chaves independentes e HMAC validado antes de executar domínio |
| DNS consulta | SEG p.3 | C1 recebe `192.168.0.10` para `servidor1`; logs nas duas pontas |
| DNS atualização | SD p.2; SEG p.3 | Três clientes atualizam tabelas; `servidor1=192.168.0.111`, mais mudanças em 4 e 9 |
| DNS multicast | SEG p.3 | Três JVMs recebem multicast real e validam seus registros |
| DNS inválido/adulterado | SEG p.3 | `servidor99` gera erro; HMAC inválido é descartado sem processamento |
| Diretório | SD p.3; SEG p.3 | S1/S2/S3 registrados com segurança; cliente recebe lista ativa completa |
| Balanceamento | SD p.3; SEG p.4 | `10+20` e `5*4`, seleção alternada e quatro operações disponíveis |
| Descoberta negativa | SEG p.4 | Módulo não cadastrado, conexão falha e HMAC de negociação inválido não travam processos |
| P2P válido | SD p.3; SEG p.4 | P0/P1/P2/P3 para arquivo35, validação por salto e resposta cifrada a P0 |
| P2P entrada inválida | SD p.3; SEG p.5 | P1/P4 rejeitam 99/ABC antes de criptografia/conexão daquela busca |
| P2P adulterado | SEG p.5 | P5 descarta mensagem de P4 e não encaminha a P0 |
| CDN HIT/MISS | SD p.5–6; SEG p.7 | GeoDNS UDP, conteúdo TCP, primeiro MISS/segundo HIT, tempos e HMAC nos logs |
| CDN TTL | SD p.6; SEG p.7 | HIT antes de dez segundos; MISS depois, com conteúdo atualizado |
| CDN invalidação | SD p.6; SEG p.7 | `INVALIDATE /arquivo30.ext` TCP protegido, remoção em todos e próximo MISS |
| CDN limites | SD p.5 | Origem com mil arquivos; cache de cada Edge com no máximo cem |
| CDN erro | SEG p.7 | arquivoXYZ não chega à origem; MAC incorreto/ausente/hash sem chave fecha só a conexão afetada |
| Apresentação | SD p.6–7; SEG p.8 | Até oito minutos, operação por vez, execução e explicação do código/erros |

## 10. Testes, evidências e falhas controladas

- Manter JUnit e testes com sockets/JVMs existentes; adaptar os que assumem assinatura/chave nova em cada mensagem para o novo contrato de sessão. Não apagar testes de validação para fazer a suíte passar.
- Segurança: duas chaves independentes; OAEP/PSS explícitos; confirmação com HMAC válido; contexto/par incorretos; assinatura de oferta falsa; HMAC adulterado e hash sem chave; rejeição antes de entregar bytes; nonce único em duas direções; sequência repetida/reordenada; oferta repetida sem zerar contadores; reinício com sessão descartada.
- Transporte: TCP truncado/negativo/excessivo, EOF, timeout e várias mensagens; UDP acima do limite; tamanho real do handshake e multicast agregado; processo continua após pacote inválido.
- Domínio: ao menos os cenários da matriz, incluindo evidência de **nenhuma chamada à origem** e **nenhum encaminhamento a P0** nos casos negativos respectivos.
- Testes de TTL/validade usam relógio controlado; concorrência usa sinais/latches. Não depender de sleeps arbitrários ou de porta fixa nos testes.
- Para a gravação, disponibilizar uma ação explícita de teste que altera o HMAC depois de produzir um pacote válido. Ela não pode desligar a validação no receptor, duplicar a implementação criptográfica ou virar modo inseguro de operação.
- Comparar estado antes/depois da falha: tabela DNS, número de encaminhamentos, cache e calculadora. Registrar falhas sem despejar segredos ou stack traces repetitivos.
- `./gradlew check` deve agregar os testes dos cinco módulos ao final. Não criar infraestrutura de benchmark, testes de nuvem ou camadas adicionais para isso.

## 11. Ordem de implementação e alcance dos arquivos

### Etapa A — Adequar segurança aos requisitos reais

- Alterar `CryptoProfile`, `SecureEnvelope`, transportes e testes; acrescentar somente o objeto concreto de sessão necessário.
- Reutilizar `KeyFiles`, `LocalIdentity`, `TrustStore`, `ReplayGuard`, tipos de resultado e CLI na medida em que atendem ao novo fluxo. Não conservar API sem chamadas apenas por compatibilidade hipotética.
- Atualizar `modules/security/README.md`: sessão, papel real de RSA/PSS/HMAC, chaves independentes, falhas, versão de protocolo e exemplo entre dois processos.
- Saída: handshake e várias mensagens AES/HMAC em TCP e UDP entre duas JVMs, autenticidade de identidade preservada, falhas HMAC demonstráveis e sem RSA por mensagem normal.

### Etapa B — Mini-DNS e descoberta

- Criar builds Java/aplicação e dependência `project(":security")` nos dois módulos; implementar clientes/servidores e testes, sem compartilhar domínio.
- DNS completo: multicast real, três clientes, registrador, consultas e erros exigidos.
- Descoberta completa: três calculadoras, três clientes, lista cifrada e round robin, inclusive erro de serviço e falha de canal.

### Etapa C — P2P e CDN

- Habilitar `p2p-naming` e `cdn` no `settings.gradle.kts`; criar seus builds e testes.
- P2P: seis processos, casos válidos/inválidos/adulterados e logs armazenados.
- CDN: GeoDNS UDP, origem e três Edges TCP, mil/cem arquivos, HIT/MISS/TTL, invalidação protegida e recusa de HMAC inválido.

### Etapa D — Documentar e entregar

- Atualizar `README.md` com nomes corretos dos cinco módulos; README de cada projeto com comandos reais, portas, ordem, erros e limites.
- Copiar esta revisão para `docs/pratica-off1-plano-implementacao.md` quando houver permissão; roteiro enxuto de apresentação em `docs/roteiro-apresentacao.md`.
- Reutilizar `installDist` para executar muitas JVMs sem vários builds Gradle concorrentes. Scripts de preparação geram chaves locais novas e aguardam prontidão dos processos uma vez; encerrar somente PIDs que iniciaram.
- Preservar os dois PDFs, alterações do usuário, chaves e dados existentes. Não realizar limpeza ampla nem sobrescrever arquivos de origem durante geração.

Prioridade sugerida: 17/10 segurança; 18/10 DNS/descoberta/P2P; 19/10 CDN e integração; 20/10 correções, vídeo e envio antecipado. A dupla pode dividir exercícios depois de estabilizar a API de sessão; sem atribuir automaticamente autoria de código.

## 12. Execução e entrega

| Processo | Transporte/porta sugerida |
| --- | --- |
| Mini-DNS | UDP 5300 |
| Notificações DNS | Multicast UDP 5301, grupo/interface local explícitos |
| Diretório | TCP 6000 |
| Calculadoras | TCP 6101–6103 |
| P0–P5 | TCP 7000–7005 |
| Origem CDN | TCP 8000 |
| Edges | TCP 8001–8003 |
| GeoDNS | UDP 5354, evitando conflito comum com mDNS em 5353 |

Portas são escolhas locais, não números impostos pelo enunciado. Unicast usa `127.0.0.1`; multicast requer interface adequada e confinamento local na demonstração. Cada papel é processo independente, mas os quatro exercícios não precisam rodar simultaneamente.

Vídeo: breve introdução às tecnologias; mostrar RSA no handshake e HMAC nas mensagens; demonstrar cada exercício e seus erros obrigatórios; abrir o código e explicar a organização. Ensaiar abaixo de oito minutos e iniciar os processos antes de gravar para não consumir o tempo com geração de chaves/quarentena.

Pacote no padrão `seu-nome-pratica-off1`, ajustado à identificação da dupla, com fontes, wrapper, documentos e instruções. Não incluir chaves privadas, caches de build ou configurações pessoais. Confirmar no SIGAA a forma de anexar/referenciar o vídeo. Preparar dependências antes se a apresentação precisar ocorrer sem internet; o título da prática não implica por si só build totalmente offline.

## 13. Limites que devem aparecer na explicação

- HMAC não é hash sem chave e não substitui a vinculação de identidades no handshake. PSS foi preservado para essa vinculação, embora o algoritmo específico de assinatura não seja prescrito pelos PDFs.
- O protocolo didático não é TLS/DTLS, não foi auditado formalmente, não é pós-quântico e não oferece forward secrecy com transporte RSA duradouro.
- Replay na sessão e no handshake são controles distintos. Não declarar proteção a reinícios se remover quarentena/expiração sem substituir o mecanismo.
- Multicast agregado resolve o caso de três clientes, não gestão escalável de grupos. Não compartilhar chaves privadas ou uma chave AES/HMAC única entre todos os projetos.
- Registro TCP não detecta todo travamento silencioso; perda de UDP não implica entrega garantida. Não acrescentar entrega exatamente uma vez, filas ou recuperação distribuída como requisitos que os PDFs não pediram.
- Invalidação estrita depende de atualizações pelo procedimento de manutenção; não prometer consistência para edição externa dos arquivos ou alta disponibilidade sob partições.
- O trabalho só estará concluído quando os casos funcionais **e** de segurança da matriz forem demonstráveis. Os 15 testes anteriores não comprovam conformidade com o novo PDF.
