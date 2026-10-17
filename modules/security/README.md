# Módulo `security`

Módulo pequeno de identidade, handshake RSA e proteção de mensagens. Usa apenas as
primitivas criptográficas padrão do JDK; não abre sockets nem implementa transporte.
É material didático, não substitui TLS/DTLS e não é protocolo de produção.

## Protocolo

- RSA-OAEP/SHA-256 transporta uma chave AES-256 e uma chave HMAC-SHA-256 independentes.
- Cada frame usa AES-256-GCM, HMAC-SHA-256 e assinatura RSA-PSS/SHA-256.
- O `READY` cifrado confirma que o destinatário recuperou as chaves da sessão.
- O cabeçalho contém identidade, sessão, direção e sequência. O contador de envio por
  direção forma o nonce GCM; a mesma instância da sessão não reutiliza a sequência.
- `SecureSession.open(frame)` devolve os bytes após validar HMAC, assinatura e tag GCM.
  Os módulos consumidores validam o formato e a regra de domínio depois disso.
- OAEP, GCM e PSS usam parâmetros explícitos. O HMAC é mantido porque o enunciado o
  exige, embora GCM também autentique os dados.

## Chaves e confiança local

Gere um par de arquivos separado para cada identidade:

```bash
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-server --directory security-keys/mini-dns/dns-server'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-1 --directory security-keys/mini-dns/dns-client-1'
```

Cada diretório tem chaves privadas e públicas distintas para OAEP e PSS. A aplicação
carrega a identidade local com `LocalIdentity.load(...)` e os pares públicos confiáveis
com `TrustedIdentity.load(nome, diretório)`. Distribua somente os arquivos
`transport-public.pem` e `signing-public.pem` por um canal confiável; nunca aceite uma
chave recebida pela rede como confiável. Arquivos privados não devem ser compartilhados
nem versionados. O comando de geração não sobrescreve chaves existentes.

## Uso pela aplicação

O módulo oferece `SecureHandshake.create(...)`, `SecureHandshake.accept(...)`,
`SecureHandshake.confirm(...)` e `SecureSession.seal/open(...)`. A aplicação faz o
handshake e a leitura/escrita dos bytes com `Socket` ou `DatagramSocket` diretamente.
Ela também é responsável por limites de transporte, timeouts, threads, multicast,
reenvios e logs.

No receptor, a configuração local associa nomes de participantes aos seus pares
`TrustedIdentity`; a oferta identifica o remetente, mas não fornece sua chave pública.

## Limitações assumidas

- Não há detecção de replay. Um frame válido reenviado pode entregar os mesmos bytes à
  aplicação outra vez e repetir uma operação.
- Uma oferta de handshake antiga pode reinstalar a mesma chave de sessão e reiniciar o
  contador, com risco de reutilização de nonce GCM. Evitar isso exigiria redesenhar o
  handshake; esta versão simples não o faz.
- O módulo não implementa PKI, certificados, negociação de algoritmos, renovação de
  chaves ou transporte confiável. UDP pode perder ou reordenar datagramas.
- Chaves privadas PKCS#8 não são cifradas em repouso. Proteja os diretórios locais.

## Testes

```bash
./gradlew :security:test
```

Os testes cobrem handshake, ida e volta, HMAC, assinatura e confiança local. A execução
entre processos e os cenários do Mini-DNS são demonstrados pela aplicação.
