# Escopo mínimo de segurança — Prática Offline 1

Este documento separa os requisitos acadêmicos das escolhas feitas na implementação,
para manter o trabalho didático e evitar construir uma infraestrutura de produção.

## Requisitos do enunciado

- Executar os componentes como processos independentes e usar sockets TCP/UDP e
  threads conforme cada exercício.
- Usar criptografia híbrida: RSA no estabelecimento da sessão e AES nas mensagens.
- Validar HMAC nos casos especificados, rejeitar mensagens adulteradas e não executar
  operações com mensagens inválidas.
- Tratar entradas inválidas e erros sem travar os demais componentes.
- Registrar envio, recebimento e validação criptográfica nos casos pedidos.
- Demonstrar os cenários funcionais e negativos descritos no PDF. O PDF não exige
  JUnit nem uma suíte automatizada específica.

## Requisito adicional acordado para este projeto

O diagrama fornecido pelo usuário exige assinatura digital das comunicações. Portanto,
as mensagens também devem ser assinadas pelo remetente e verificadas pelo destinatário.
O PDF enfatiza RSA no handshake e HMAC nas mensagens; a assinatura por mensagem é uma
exigência adicional adotada para seguir o diagrama, não algo explicitado nos exemplos
textuais do PDF.

## Escolhas de implementação, não requisitos explícitos do PDF

Essas escolhas podem ser revistas para simplificar, desde que os requisitos acima
continuem atendidos:

- RSA-3072, AES-256, RSA-PSS e parâmetros criptográficos específicos;
- manifesto próprio de confiança, fingerprints e pares RSA separados;
- quarentena inicial de 34 segundos, cache de replay com 100 mil entradas, janela de
  sequência de 64 mensagens e tolerância de relógio;
- limites exatos de payload, enquadramento próprio e adaptadores genéricos TCP/UDP;
- quantidade e forma dos testes automatizados entre JVMs.

O fato de um controle não estar especificado no PDF não significa que seja seguro
removê-lo sem revisar o protocolo e os testes que dependem dele.

## O que não deve ser removido ao simplificar

- Uso de `SecureRandom`, nonce AES não repetido com a mesma chave e chaves AES/HMAC
  distintas.
- Verificação da identidade por uma chave pública previamente confiável; não aceitar
  automaticamente uma chave recebida no mesmo canal não autenticado.
- Verificação de assinatura, HMAC e cifra antes de entregar o conteúdo à aplicação.
- Proteção das chaves privadas, validação dos tamanhos/formato das mensagens e ausência
  de fallback para texto claro.

## Critério de simplicidade

A implementação deve servir para explicar os requisitos e demonstrar os casos do
trabalho. Evitar PKI, TLS/DTLS, rotação automática, negociação de algoritmos,
recuperação distribuída e abstrações para cenários que a prática não pede.
