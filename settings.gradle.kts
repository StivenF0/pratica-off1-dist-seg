rootProject.name = "pratica-off1-dist-seg"

include(
    "security",
    "mini-dns",
    "service-discovery",
//    "p2p-naming",
//    "cdn",
)

project(":security").projectDir = file("modules/security")
project(":mini-dns").projectDir = file("modules/mini-dns")
project(":service-discovery").projectDir = file("modules/service-discovery")
//project(":p2p-naming").projectDir = file("modules/p2p-naming")
//project(":cdn").projectDir = file("modules/cdn")
