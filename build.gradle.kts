plugins {
    base
}

allprojects {
    repositories {
        mavenCentral()
    }
}

tasks.named("check") {
    dependsOn(":security:check", ":mini-dns:check")
}
