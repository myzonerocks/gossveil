// The Android plugin reads the SDK from the environment or from local.properties, and a
// machine that has the SDK in its usual place has neither; point at it once, in a file that
// is never committed, so a plain ./gradlew works.
run {
    val fromEnvironment = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    val properties = File(rootDir, "local.properties")
    if (fromEnvironment.isNullOrBlank() && !properties.exists()) {
        val home = System.getProperty("user.home")
        val usual = listOf(File(home, "Library/Android/sdk"), File(home, "Android/Sdk"))
        usual.firstOrNull { it.isDirectory }?.let { sdk ->
            properties.writeText("sdk.dir=${sdk.absolutePath}\n")
        }
    }
}

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "gossveil"
include(":lib")
