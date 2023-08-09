Jsign Gradle Plugin
-------------------

Deployment procedure:
* Publish the new version of jsign-core to Maven Central
* Add the API key from https://plugins.gradle.org in `~/.gradle/gradle.properties`
* Update the version in `build.gradle`
* Run: `gradle publishPlugins`
