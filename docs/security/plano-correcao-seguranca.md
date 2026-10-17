# Correção do módulo de segurança

## Aplicado

- Classes agrupadas nos pacotes `identity`, `communication` e `cli`.
- Frames `READY` e de aplicação agora usam AES-GCM, HMAC-SHA-256 e assinatura RSA-PSS.
- A versão dos frames foi incrementada; frames antigos são rejeitados.
- Multicast envia um frame por sessão/destinatário, mantendo o limite UDP de 1200 bytes.
- Documentação e testes foram ajustados ao novo formato.

## Validação

`./gradlew check` e os launchers de `security` e Mini-DNS passaram. O teste de
multicast real também passou nesta execução.

## Pendente

O teste de multicast ainda pode transformar falhas funcionais em testes ignorados;
essa correção continua pendente, conforme combinado. A demonstração deve ser feita
na interface/rede usada na apresentação.
