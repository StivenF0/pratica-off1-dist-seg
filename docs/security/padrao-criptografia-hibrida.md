# Padrão de criptografia híbrida

As mensagens entre processos usam RSA-OAEP no estabelecimento da sessão e AES-GCM nos
dados. HMAC-SHA-256 é mantido por exigência do enunciado; RSA-PSS assina a oferta e os
frames da sessão conforme o diagrama do grupo.

## Frame da sessão

```text
cabeçalho || ciphertext AES-GCM com tag || HMAC-SHA-256 || assinatura RSA-PSS
```

- O cabeçalho inclui sessão, direção e sequência; direção e contador de envio formam o
  nonce GCM.
- O HMAC cobre cabeçalho e ciphertext com tag. A assinatura cobre esses campos e o
  HMAC.
- O destinatário valida o HMAC, a assinatura e a tag GCM antes de entregar os bytes à
  aplicação.
- O `READY` é cifrado e autenticado para confirmar que o destinatário recuperou as
  chaves da sessão.

As chaves públicas confiáveis são carregadas de arquivos locais configurados para cada
identidade. Não há manifesto próprio nem aceitação automática de chaves recebidas pela
rede. Chaves privadas permanecem locais.

## Uso nos projetos

`security` expõe identidade, handshake e proteção/abertura de bytes. Os projetos fazem
diretamente a leitura e escrita em `Socket`, `DatagramSocket` ou `MulticastSocket`, e
tratam enquadramento, timeouts, threads e logs.

## Limitações de replay

Não existe detecção de replay: um frame válido repetido pode repetir a operação. O
contador evita reutilizar nonces durante o envio numa instância de sessão, mas uma
oferta de handshake antiga pode reinstalar as mesmas chaves e reiniciar esse contador,
com risco de reutilização do nonce GCM. Evitar esse risco exige um handshake diferente;
isso não faz parte da versão didática simplificada.

HMAC, hash sem chave e assinatura são mecanismos distintos: um não substitui o outro.
Esta implementação não substitui TLS/DTLS e não é protocolo de produção.

## Multicast do Mini-DNS

O servidor envia um datagrama multicast protegido para cada sessão de cliente. Os
clientes recebem também os frames dos demais participantes e descartam os que não
conseguem abrir com sua sessão. UDP não garante entrega.

## Testes

Os testes cobrem handshake, abertura de mensagens, falhas de HMAC/assinatura e os casos
do Mini-DNS. A demonstração separada por processos é feita manualmente. O teste
multicast pode ser ignorado no ambiente local se a interface não entregar os pacotes;
isso não prova que multicast funciona numa rede real.
