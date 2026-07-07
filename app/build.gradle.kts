import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val appVersionName = "11"
val releaseApkBaseName = "WDTT-Plus"

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(localPropertiesFile.inputStream())
}

android {
    namespace = "com.wdtt.plus"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.wdtt.plus"
        minSdk = 28
        targetSdk = 35
        versionCode = 11
        versionName = appVersionName
        buildConfigField("String", "MOD_RELEASE_DATE", "\"07.07.2026\"")

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
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            if (keyFile != null) {
                // Резолвим путь: если начинается с "..", берём от корня проекта
                val resolvedFile = if (keyFile.startsWith("..")) {
                    // ../release.keystore -> корень проекта / release.keystore
                    file(rootDir.resolve(keyFile.substring(3)))
                } else {
                    file(keyFile)
                }
                if (resolvedFile.exists()) {
                    storeFile = resolvedFile
                    storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
                    keyAlias = localProperties.getProperty("KEY_ALIAS")
                    keyPassword = localProperties.getProperty("KEY_PASSWORD")
                } else {
                    println("WARNING: Keystore file not found: $keyFile (resolved: ${resolvedFile.absolutePath})")
                }
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            val resolvedFile = if (keyFile != null && keyFile.startsWith("..")) {
                file(rootDir.resolve(keyFile.substring(3)))
            } else if (keyFile != null) {
                file(keyFile)
            } else null
            
            if (resolvedFile != null && resolvedFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
                println("✅ Signing config applied: ${resolvedFile.absolutePath}")
            } else {
                println("⚠️ WARNING: Keystore not found, using debug signing")
                println("   Looked for: ${resolvedFile?.absolutePath ?: keyFile}")
            }
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
        checkReleaseBuilds = false
        abortOnError = false
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
                        go build -trimpath -ldflags="-s -w -checklinkname=0" -buildmode=pie \
                        -o "${'$'}jni_dir/${'$'}abi/libclient.so" .
                else
                    env GOOS=android GOARCH="${'$'}goarch" CGO_ENABLED=1 CC="${'$'}ndk_bin/${'$'}cc" \
                        go build -trimpath -ldflags="-s -w -checklinkname=0" -buildmode=pie \
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
                go build -trimpath -ldflags="-s -w" -o "${'$'}out" .
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

tasks.register<Exec>("nameReleaseApks") {
    group = "build"
    description = "Copies release APKs to filenames with app name and version."

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

tasks.matching { it.name == "assembleRelease" }.configureEach {
    finalizedBy("nameReleaseApks")
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
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("com.wireguard.android:tunnel:1.0.20230706")
    implementation("com.github.mwiede:jsch:0.2.16")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260522")
}
