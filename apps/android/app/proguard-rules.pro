# The relay's original-destination reader is called across JNI by exact symbol
# name; R8 must not rename the class or its native method.
-keepclasseswithmembernames class * {
    native <methods>;
}
-keep class com.apiaxess.client.capture.OriginalDst { *; }

# kotlinx.serialization ships its own consumer rules; keep our @Serializable
# models' synthetic serializers as a belt-and-braces measure.
-keepclassmembers class com.apiaxess.client.** {
    *** Companion;
}
-keepclasseswithmembers class com.apiaxess.client.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp/Okio ship their own rules; nothing extra required here.
