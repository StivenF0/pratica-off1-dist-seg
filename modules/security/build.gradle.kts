plugins {
    `java-library`
    application
}

group = "br.edu.ufersa.pratica"
version = "1.0.0"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

application {
    mainClass.set("br.edu.ufersa.pratica.security.cli.SecurityCli")
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
