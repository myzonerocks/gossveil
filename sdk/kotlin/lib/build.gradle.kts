import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("com.vanniktech.maven.publish")
}

// The native core is built by zig into zig-out at the repository root: one
// shared library per Android ABI for the AAR, and a host library the JVM
// unit tests load.
val repoRoot = rootProject.projectDir.parentFile.parentFile
val androidLibs = File(repoRoot, "zig-out/android")
val hostLibs = File(repoRoot, "zig-out/jni")

android {
    namespace = "com.gossveil"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs(androidLibs)
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.all {
            it.systemProperty("java.library.path", hostLibs.absolutePath)
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

// Publishes the AAR, the prebuilt .so already inside, to Maven Central through
// the Sonatype Central Portal. Coordinates and POM come from gradle.properties;
// the token and signing key come from the release job. A source build without
// a key (JitPack, a fork) publishes unsigned instead of failing.
// A file repository under build/ so a sibling checkout consumes the AAR by path
// before anything is published to a registry.
publishing {
    repositories {
        maven {
            name = "local"
            url = uri(layout.buildDirectory.dir("repo"))
        }
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    if (project.findProperty("signingInMemoryKey") != null) {
        signAllPublications()
    }
    coordinates("io.github.avosa", "gossveil", project.property("VERSION_NAME").toString())
}
