buildscript {
    repositories {
        mavenLocal()
    }

    dependencies {
        classpath("net.jsign:jsign-gradle-plugin:7.0")
    }
}

apply(plugin = "net.jsign")

task("sign") {
    doLast {
        val jsign = project.extensions.getByName("jsign") as groovy.lang.Closure<*>
        jsign("file"      to "application.exe",
              "name"      to "My Application",
              "url"       to "http://www.example.com",
              "keystore"  to "keystore.p12",
              "alias"     to "test",
              "storepass" to "secret",
              "tsaurl"    to "http://timestamp.sectigo.com")
    }
}
