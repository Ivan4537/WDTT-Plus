-keep class com.jcraft.jsch.** { *; }
-keep class com.mwiede.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
-dontwarn com.mwiede.jsch.**

# SafeGoBackend reuses the dependency's JNI exports through a checked bridge.
-keep class com.wireguard.android.backend.GoBackend {
    private static native *** *(...);
}
-keep class com.wireguard.android.backend.Statistics {
    <init>();
    void add(com.wireguard.crypto.Key, long, long, long);
}
