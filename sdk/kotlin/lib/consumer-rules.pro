# The JNI entry is resolved by name at load time.
-keepclassmembers class com.gossveil.Native {
    native <methods>;
}
-keep class com.gossveil.*Exception { *; }
