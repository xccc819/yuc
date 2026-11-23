plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    // 持久化：内含 Win/mac/Linux 的 native，会被下面 jar 任务一起解包进 yuc-1.0.jar
    implementation("org.xerial:sqlite-jdbc:3.36.0.3")
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.named<Jar>("jar") {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveFileName.set("yuc-1.0.jar")
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}