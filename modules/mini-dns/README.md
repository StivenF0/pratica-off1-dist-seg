# Mini-DNS seguro

Servidor DNS UDP, três clientes e um registrador; cada papel roda em processo separado.
O módulo `security` cuida apenas das chaves, handshake e frames criptográficos. O
Mini-DNS usa diretamente `DatagramSocket` e `MulticastSocket`.

## Preparar as chaves

Gere as identidades uma vez:

```bash
mkdir -p security-keys/mini-dns
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-server --directory security-keys/mini-dns/dns-server'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-1 --directory security-keys/mini-dns/dns-client-1'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-2 --directory security-keys/mini-dns/dns-client-2'
./gradlew :security:run --args='generate-keys --project mini-dns --identity dns-client-3 --directory security-keys/mini-dns/dns-client-3'
./gradlew :security:run --args='generate-keys --project mini-dns --identity registrar --directory security-keys/mini-dns/registrar'
```

Não há manifesto de confiança. Cada processo carrega sua chave privada local e as
chaves públicas dos participantes esperados a partir dos diretórios com esses nomes.
Em máquinas diferentes, copie para cada processo somente os arquivos públicos OAEP e
PSS dos pares remotos; mantenha suas chaves privadas locais. Não versione arquivos de
chave.

## Executar

Escolha uma interface IPv4 que suporte multicast (`ip -brief link` ajuda). Gere o
launcher uma vez e use terminais separados:

```bash
./gradlew :mini-dns:installDist

# Servidor: unicast UDP 5300; notificações em 239.255.42.99:5301
modules/mini-dns/build/install/mini-dns/bin/mini-dns server --keys-dir security-keys/mini-dns --interface wlan0

# Abra três terminais para os clientes
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-1 --keys-dir security-keys/mini-dns --interface wlan0
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-2 --keys-dir security-keys/mini-dns --interface wlan0
modules/mini-dns/build/install/mini-dns/bin/mini-dns client --identity dns-client-3 --keys-dir security-keys/mini-dns --interface wlan0

# Execute depois que os três clientes resolverem servidor1
modules/mini-dns/build/install/mini-dns/bin/mini-dns registrar --keys-dir security-keys/mini-dns
```

Cada cliente começa consultando `servidor1` (`192.168.0.10`). Digite outro nome para
consultar; `servidor99` exibe `Erro na entrada de dados. Tente outra vez!`. Digite
`sair` para fechar o cliente.

O registrador demonstra as atualizações `servidor1 → 192.168.0.111`,
`servidor4 → 192.168.0.144` e `servidor9 → 192.168.0.199`. O DNS aceita essas
atualizações somente da identidade `registrar` e envia um frame multicast separado por
sessão de cliente. Cada frame cabe no limite UDP de 1200 bytes; UDP não garante entrega.

O handshake UDP envia uma oferta e aguarda o `READY`, sem quarentena ou retries
automáticos. Se o datagrama se perder, execute o processo novamente.

## Demonstração de HMAC inválido

```bash
modules/mini-dns/build/install/mini-dns/bin/mini-dns test-corrupt-hmac --keys-dir security-keys/mini-dns
```

O comando envia uma mensagem válida com o HMAC alterado. O DNS deve registrar
`HMAC_FAIL`, descartar o pacote sem executar o `UPDATE` e continuar atendendo aos
clientes.

## Testes e limites

```bash
./gradlew :mini-dns:test
./gradlew check
```

O teste multicast ainda pode ser marcado como ignorado quando a interface local não
entrega multicast; isso não comprova entrega numa rede real. A limitação foi deixada
para revisão posterior.

Esta implementação não detecta replay: uma mensagem válida repetida pode repetir a
operação, e uma oferta antiga pode reinstalar as mesmas chaves e reiniciar o contador
GCM. É uma demonstração didática, não um protocolo de produção.
