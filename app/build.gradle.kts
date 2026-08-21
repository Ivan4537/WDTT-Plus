import java.io.File
import java.util.Properties
import org.gradle.api.DefaultTask
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

abstract class VerifyReleaseConfiguration : DefaultTask() {
    @get:Input
    abstract val keystorePath: Property<String>

    @get:Input
    abstract val credentialsComplete: Property<Boolean>

    @get:Input
    abstract val productionDomain: Property<Boolean>

    @get:Input
    abstract val releaseAuditRequired: Property<Boolean>

    @get:Input
    abstract val releaseAuditPath: Property<String>

    @TaskAction
    fun verify() {
        require(File(keystorePath.get()).isFile) {
            "Release signing keystore is required."
        }
        require(credentialsComplete.get()) {
            "Complete release signing credentials are required."
        }
        require(productionDomain.get()) {
            "Release builds must use the production WDTT Plus domain."
        }
        require(
            !releaseAuditRequired.get() ||
                File(releaseAuditPath.get()).let { it.isFile && it.canExecute() }
        ) {
            "The local release audit is required but unavailable."
        }
    }
}

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val appVersionName = "15"
val releaseApkBaseName = "WDTT-Plus"

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

fun buildConfigString(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val wdttPlusDomain = localProperties.getProperty("WDTT_PLUS_DOMAIN")
    ?.trim()
    ?.trimEnd('/')
    ?.takeIf { it.isNotBlank() }
    ?: "wdttplus.ru"
val remoteActionPreview = providers.gradleProperty("REMOTE_ACTION_PREVIEW")
    .orNull
    ?.toBooleanStrictOrNull()
    ?: false
val releaseKeystoreProperty = localProperties.getProperty("KEYSTORE_FILE")
    ?.trim()
    .orEmpty()
val releaseKeystoreFile = when {
    releaseKeystoreProperty.startsWith("..") ->
        rootDir.resolve(releaseKeystoreProperty.removePrefix("../"))
    releaseKeystoreProperty.isNotBlank() -> file(releaseKeystoreProperty)
    else -> null
}
val releaseCredentialsComplete =
    listOf("KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD")
        .all { !localProperties.getProperty(it).isNullOrBlank() }
val localReleaseAuditRequired = rootProject.file("release.keystore").exists()
val localReleaseAudit = rootProject.file("release-audit")

android {
    namespace = "com.wdtt.plus"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.wdtt.plus"
        minSdk = 28
        targetSdk = 35
        versionCode = 15
        versionName = appVersionName
        buildConfigField("String", "MOD_RELEASE_DATE", "\"21.08.2026\"")
        buildConfigField("String", "WDTT_PLUS_DOMAIN", buildConfigString(wdttPlusDomain))
        manifestPlaceholders["wdttPlusDomain"] = wdttPlusDomain
        manifestPlaceholders["appLabel"] = "WDTT Plus"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    signingConfigs {
        create("release") {
            if (releaseKeystoreFile?.isFile == true) {
                storeFile = releaseKeystoreFile
                storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
                keyAlias = localProperties.getProperty("KEY_ALIAS")
                keyPassword = localProperties.getProperty("KEY_PASSWORD")
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".preview"
            versionNameSuffix = "-preview"
            manifestPlaceholders["appLabel"] = "WDTT Plus Preview"
            buildConfigField("boolean", "REMOTE_ACTION_PREVIEW", remoteActionPreview.toString())
        }
        getByName("release") {
            buildConfigField("boolean", "REMOTE_ACTION_PREVIEW", "false")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (releaseKeystoreFile?.isFile == true) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        create("preview") {
            initWith(getByName("release"))
            versionNameSuffix = "-preview-ui2"
            manifestPlaceholders["appLabel"] = "WDTT Plus Preview"
            buildConfigField("boolean", "REMOTE_ACTION_PREVIEW", "true")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/DEPENDENCIES"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = true
        abortOnError = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.setSrcDirs(listOf("src/main/jniLibs"))
        }
    }
}

val verifyReleaseConfiguration =
    tasks.register<VerifyReleaseConfiguration>("verifyReleaseConfiguration") {
        keystorePath.set(releaseKeystoreFile?.absolutePath.orEmpty())
        credentialsComplete.set(releaseCredentialsComplete)
        productionDomain.set(wdttPlusDomain == "wdttplus.ru")
        releaseAuditRequired.set(localReleaseAuditRequired)
        releaseAuditPath.set(localReleaseAudit.absolutePath)
    }

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(verifyReleaseConfiguration)
}

val goClientDir = rootProject.layout.projectDirectory.dir("go_client")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val serverAssetFile = layout.projectDirectory.file("src/main/assets/server")
val androidSdkDir = localProperties.getProperty("sdk.dir")
    ?: System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")

tasks.register<Exec>("buildNativeClient") {
    group = "build"
    description = "Builds Android libclient.so binaries from go_client sources."

    inputs.files(fileTree(goClientDir.asFile) {
        include("**/*.go", "go.mod", "go.sum")
    })
    outputs.files(
        listOf("arm64-v8a", "armeabi-v7a", "x86_64").map { abi ->
            jniLibsDir.file("$abi/libclient.so")
        }
    )

    commandLine(
        "bash",
        "-lc",
        """
            set -euo pipefail
            sdk_dir="${'$'}1"
            go_dir="${'$'}2"
            jni_dir="${'$'}3"
            if [ -z "${'$'}sdk_dir" ]; then
                echo "Android SDK not found. Set sdk.dir in local.properties or ANDROID_HOME." >&2
                exit 1
            fi
            ndk_bin="$(ls -d "${'$'}sdk_dir"/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/bin 2>/dev/null | sort -V | tail -n 1)"
            if [ -z "${'$'}ndk_bin" ]; then
                echo "Android NDK not found under ${'$'}sdk_dir/ndk." >&2
                exit 1
            fi
            build_one() {
                abi="${'$'}1"
                goarch="${'$'}2"
                cc="${'$'}3"
                goarm="${'$'}4"
                mkdir -p "${'$'}jni_dir/${'$'}abi"
                if [ -n "${'$'}goarm" ]; then
                    env GOOS=android GOARCH="${'$'}goarch" GOARM="${'$'}goarm" CGO_ENABLED=1 CC="${'$'}ndk_bin/${'$'}cc" \
                        go build -buildvcs=false -trimpath \
                        -ldflags="-s -w -checklinkname=0 -linkmode=external -extldflags=-Wl,-z,max-page-size=16384" \
                        -buildmode=pie \
                        -o "${'$'}jni_dir/${'$'}abi/libclient.so" .
                else
                    env GOOS=android GOARCH="${'$'}goarch" CGO_ENABLED=1 CC="${'$'}ndk_bin/${'$'}cc" \
                        go build -buildvcs=false -trimpath \
                        -ldflags="-s -w -checklinkname=0 -linkmode=external -extldflags=-Wl,-z,max-page-size=16384" \
                        -buildmode=pie \
                        -o "${'$'}jni_dir/${'$'}abi/libclient.so" .
                fi
            }
            cd "${'$'}go_dir"
            build_one arm64-v8a arm64 aarch64-linux-android29-clang ""
            build_one armeabi-v7a arm armv7a-linux-androideabi29-clang 7
            build_one x86_64 amd64 x86_64-linux-android29-clang ""
        """.trimIndent(),
        "bash",
        androidSdkDir.orEmpty(),
        goClientDir.asFile.absolutePath,
        jniLibsDir.asFile.absolutePath
    )
}

val verify16KbNativeLibraries = tasks.register<Exec>("verify16KbNativeLibraries") {
    group = "verification"
    description = "Verifies 16 KiB LOAD alignment for every 64-bit Android native library."
    dependsOn("mergeReleaseNativeLibs")

    val mergedNativeLibs = layout.buildDirectory.dir(
        "intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib"
    )
    inputs.dir(mergedNativeLibs)

    commandLine(
        "bash",
        "-lc",
        """
            set -euo pipefail
            lib_root="${'$'}1"
            sdk_dir="${'$'}2"
            readelf_bin="$(command -v readelf || true)"
            if [ -z "${'$'}readelf_bin" ] && [ -n "${'$'}sdk_dir" ]; then
                readelf_bin="$(ls -d "${'$'}sdk_dir"/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf 2>/dev/null | sort -V | tail -n 1)"
            fi
            if [ -z "${'$'}readelf_bin" ] || [ ! -x "${'$'}readelf_bin" ]; then
                echo "readelf is required to verify Android native page alignment." >&2
                exit 1
            fi
            found=0
            for abi in arm64-v8a x86_64; do
                abi_dir="${'$'}lib_root/${'$'}abi"
                [ -d "${'$'}abi_dir" ] || continue
                while IFS= read -r -d '' library; do
                    found=1
                    while IFS= read -r alignment; do
                        value=${'$'}((alignment))
                        if [ "${'$'}value" -lt 16384 ]; then
                            echo "Native library is not compatible with 16 KiB pages: ${'$'}library (LOAD align=${'$'}alignment)" >&2
                            exit 1
                        fi
                    done < <("${'$'}readelf_bin" -lW "${'$'}library" | awk '${'$'}1 == "LOAD" { print ${'$'}NF }')
                done < <(find "${'$'}abi_dir" -type f -name '*.so' -print0)
            done
            if [ "${'$'}found" -ne 1 ]; then
                echo "No 64-bit Android native libraries found under ${'$'}lib_root." >&2
                exit 1
            fi
            echo "All 64-bit Android native libraries use 16 KiB-compatible LOAD alignment."
        """.trimIndent(),
        "bash",
        mergedNativeLibs.get().asFile.absolutePath,
        androidSdkDir.orEmpty(),
    )
}

tasks.matching { it.name == "packageRelease" }.configureEach {
    dependsOn(verify16KbNativeLibraries)
}

tasks.matching {
    it.name.startsWith("merge") &&
        (it.name.endsWith("NativeLibs") || it.name.endsWith("JniLibFolders"))
}.configureEach {
    dependsOn("buildNativeClient")
}

tasks.register<Exec>("buildServerAsset") {
    group = "build"
    description = "Builds the Linux wdtt-server binary embedded into Android deploy assets."
    workingDir(rootProject.layout.projectDirectory.asFile)

    inputs.files(fileTree(rootProject.layout.projectDirectory.asFile) {
        include("*.go", "go.mod", "go.sum")
        exclude("build/**", "app/**", "go_client/**")
    })
    outputs.file(serverAssetFile)

    commandLine(
        "bash",
        "-lc",
        """
            set -euo pipefail
            out="${'$'}1"
            mkdir -p "$(dirname "${'$'}out")"
            env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
                go build -buildvcs=false -trimpath -ldflags="-s -w" -o "${'$'}out" .
        """.trimIndent(),
        "bash",
        serverAssetFile.asFile.absolutePath
    )
}

tasks.matching {
    it.name.startsWith("merge") && it.name.endsWith("Assets")
}.configureEach {
    dependsOn("buildServerAsset")
}

// Lint reads the source asset/native folders directly. During assembleRelease
// the generators are in the same task graph, so make their order explicit
// without forcing public source-only lint runs to build private local artifacts.
tasks.matching { it.name.contains("Lint", ignoreCase = true) }.configureEach {
    mustRunAfter("buildServerAsset", "buildNativeClient")
}

val nameReleaseApks = tasks.register<Exec>("nameReleaseApks") {
    group = "build"
    description = "Copies release APKs to filenames with app name and version."
    dependsOn("packageRelease")

    val releaseDir = layout.buildDirectory.dir("outputs/apk/release")
    val namedReleaseDir = layout.buildDirectory.dir("outputs/apk/release/named")
    val variants = listOf("universal", "arm64-v8a", "armeabi-v7a", "x86_64")

    inputs.files(variants.map { abi -> releaseDir.map { it.file("app-$abi-release.apk") } })
    outputs.files(variants.map { abi -> namedReleaseDir.map { it.file("$releaseApkBaseName-v$appVersionName-$abi-release.apk") } })

    commandLine(
        "bash",
        "-lc",
        """
            set -euo pipefail
            release_dir="${'$'}1"
            named_dir="${'$'}2"
            app_name="${'$'}3"
            version="${'$'}4"
            mkdir -p "${'$'}named_dir"
            for abi in universal arm64-v8a armeabi-v7a x86_64; do
                cp "${'$'}release_dir/app-${'$'}abi-release.apk" "${'$'}named_dir/${'$'}app_name-v${'$'}version-${'$'}abi-release.apk"
            done
        """.trimIndent(),
        "bash",
        releaseDir.get().asFile.absolutePath,
        namedReleaseDir.get().asFile.absolutePath,
        releaseApkBaseName,
        appVersionName
    )
}

val auditReleaseApks = tasks.register<Exec>("auditReleaseApks") {
    group = "verification"
    description = "Runs the configured local source and APK publication audit."
    dependsOn(nameReleaseApks)
    enabled = localReleaseAuditRequired

    val namedReleaseDir = layout.buildDirectory.dir("outputs/apk/release/named").get().asFile
    val variants = listOf("universal", "arm64-v8a", "armeabi-v7a", "x86_64")
    val releaseApks = variants.map { abi ->
        namedReleaseDir.resolve("$releaseApkBaseName-v$appVersionName-$abi-release.apk")
    }
    inputs.files(releaseApks)
    commandLine(
        listOf(
            localReleaseAudit.absolutePath,
            rootDir.absolutePath,
        ) + releaseApks.map(File::getAbsolutePath)
    )
}

tasks.matching { it.name == "assembleRelease" }.configureEach {
    finalizedBy(auditReleaseApks)
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.browser:browser:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("com.wireguard.android:tunnel:1.0.20260102")
    implementation("com.github.mwiede:jsch:0.2.16")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260522")
}
