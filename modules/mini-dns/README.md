# Mini-DNS seguro

Servidor DNS UDP, três clientes e um registrador, cada papel executado em processo separado. Consultas, respostas e atualizações usam sessões do módulo `security`: handshake RSA-OAEP/PSS e mensagens AES-256-GCM + HMAC-SHA-256. As chaves privadas permanecem locais.

## Preparar identidades

```bash
mkdir -p security-keys/mini-dns
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-server --directory security-keys/mini-dns/dns-server'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-1 --directory security-keys/mini-dns/dns-client-1'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-2 --directory security-keys/mini-dns/dns-client-2'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-3 --directory security-keys/mini-dns/dns-client-3'
./gradlew :security:run --args='generate-keys --project mini-dns --identity registrar --directory security-keys/mini-dns/registrar'
./gradlew :security:run --args='create-trust-manifest --project mini-dns --directory security-keys/mini-dns --output security-keys/mini-dns/trust.tsv --identities dns-server,dns-client-1,dns-client-2,dns-client-3,registrar'
```

Distribua o manifesto por canal confiável. Todos os processos usam a mesma raiz e o mesmo manifesto:

```text
--keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv
```

## Executar a demonstração

Escolha uma interface IPv4 que suporte multicast (`ip -brief link` ajuda). O servidor e os clientes aguardam a quarentena antirreplay de 34 segundos antes de abrir sockets. Gere o launcher uma vez e use terminais separados, sem vários builds Gradle concorrentes:

```bash
./gradlew :mini-dns:installDist

# Servidor DNS: UDP unicast 5300; notificações multicast 239.255.42.99:5301
modules/mini-dns/build/install/mini-dns/bin/mini-dns server --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv --interface wlan0

# Inicie estes três processos e deixe-os na tela para ver as atualizações.
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-1 --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv --interface wlan0
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-2 --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv --interface wlan0
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-3 --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv --interface wlan0

# Execute depois que C1, C2 e C3 resolverem servidor1.
modules/mini-dns/build/install/mini-dns/bin/mini-dns registrar --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv
```

Cada cliente inicia com `RESOLVE servidor1` e mantém uma tabela local durante sua execução. Digite outro nome no terminal do cliente para consultar; `servidor99` retorna exatamente `Erro na entrada de dados. Tente outra vez!`. Digite `sair` para fechar o cliente.

O registrador envia, em sessões autenticadas, as três alterações exigidas: `servidor1 → 192.168.0.111`, `servidor4 → 192.168.0.144` e `servidor9 → 192.168.0.199`. O DNS só aceita esses valores do identity `registrar`, atualiza o mapa e envia cada notificação em um datagrama multicast com três registros AES/HMAC independentes. Cada cliente recebe e valida apenas o registro da própria sessão antes de alterar a tabela.

O cliente usa um socket unicast efêmero e outro socket associado ao grupo multicast. Ambos compartilham a sessão já negociada; isso evita que três clientes no mesmo host disputem a porta UDP multicast para as respostas unicast.

## Testes de segurança

O teste explícito abaixo negocia uma sessão com a identidade `registrar`, cria um frame válido e altera somente seu HMAC antes do envio. Não desativa validação nem envia payload em claro. O DNS deve registrar `HMAC_FAIL`, descartar o pacote sem executar o `UPDATE` e continuar respondendo aos outros clientes.

```bash
modules/mini-dns/build/install/mini-dns/bin/mini-dns test-corrupt-hmac --keys-dir security-keys/mini-dns --trust security-keys/mini-dns/trust.tsv --interface wlan0
```

O grupo usa TTL 1 para não ser encaminhado por roteadores; outros dispositivos no mesmo enlace ainda podem observar os datagramas, mas cada registro contém somente dados cifrados. Algumas interfaces/ambientes virtuais bloqueiam a entrega multicast local; nesse caso, o teste de integração registra a limitação, mas isso **não** comprova a notificação em hardware/rede real. Valide a interface usada na apresentação.

```bash
./gradlew :mini-dns:test
./gradlew check
```
