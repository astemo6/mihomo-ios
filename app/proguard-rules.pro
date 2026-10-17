# gomobile bindings: the Go runtime calls back into these classes by name through JNI.
-keep class go.** { *; }
-keep class libmihomo.** { *; }
-keepclassmembers class * implements libmihomo.SocketProtector { *; }
-keepclassmembers class * implements libmihomo.Notifier { *; }

# kotlinx.serialization (the library ships its own rules; keep our @Serializable models' companions)
-keepattributes *Annotation*, InnerClasses
-keepclassmembers @kotlinx.serialization.Serializable class io.github.astemo6.mihomo.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
