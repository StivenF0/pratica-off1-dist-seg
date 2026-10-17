# Prática Offline 1 - Distribuídos e Segurança

## Autores:

- **Stiven Felipe**
- **Robert Luann**

## Estrutura do repositório

- **`modules/security`**: biblioteca compartilhada com handshake RSA e mensagens AES-256-GCM, HMAC-SHA-256 e assinatura RSA-PSS;
- **`modules/mini-dns`**: Mini-DNS para resolução de nomes;
- **`modules/service-discovery`**: Descoberta de serviços;
- **`modules/(a-decidir)`**: Nomeação P2P em overlay simplificado;
- **`modules/(a-decidir)`**: Simulação de uma CDN.

Cada diretório em `modules/` corresponde a um subprojeto Gradle independente.

O módulo `security` contém provisionamento local de chaves, handshake e proteção criptográfica de mensagens; cada projeto usa diretamente seus sockets. Consulte [`modules/security/README.md`](modules/security/README.md) para geração de identidades, confiança local, API e testes. Os projetos de Sistemas Distribuídos permanecem independentes entre si e podem depender dessa biblioteca compartilhada.

O Mini-DNS e seus comandos de execução estão documentados em [`modules/mini-dns/README.md`](modules/mini-dns/README.md).
