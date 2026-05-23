# Bluetooth Security Testing Tool - ProGuard Rules

# Kotlin
-keep class kotlin.** { *; }
-keep class kotlinx.** { *; }

# Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# Hilt/Dagger
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper { *; }

-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$ActivityContextWrapper { *; }

-keepclassmembers class * {
    @dagger.hilt.android.AndroidEntryPoint *;
    @dagger.hilt.android.HiltAndroidApp *;
}

-keep class dagger.hilt.android.internal.** { *; }
-keep interface dagger.hilt.** { *; }

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep class * extends androidx.room.RoomDatabase
-dontwarn androidx.room.paging.**

# Serialization
-keepattributes Signature
-keepattributes *Annotation*
-keepclassmembers,allowshrinking,allowobfuscation class * {
    @kotlinx.serialization.SerialName <fields>;
}

# Bluetooth
-keep class android.bluetooth.** { *; }
-keep class androidx.bluetooth.** { *; }

# Compose
-keep class androidx.compose.** { *; }
-keepclassmembers class androidx.compose.** { *; }

# Navigation
-keep class androidx.navigation.** { *; }

# Lifecycle
-keep class * extends androidx.lifecycle.ViewModel
-keep class * extends androidx.lifecycle.AndroidViewModel
-keepclassmembers class * extends androidx.lifecycle.LiveData { *; }
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>();
}

# DataStore
-keep class androidx.datastore.** { *; }

# WorkManager
-keep class androidx.work.** { *; }
-dontwarn androidx.work.impl.**

# PDF (iText)
-keep class com.itextpdf.** { *; }
-dontwarn com.itextpdf.**

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keepattributes Signature
-keepattributes InnerClasses
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Retrofit
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }
-keep interface retrofit2.** { *; }
-keepattributes Signature
-keepattributes Exceptions

# JSON
-keepattributes Signature
-keepattributes *Annotation*
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# AndroidX
-keep class androidx.** { *; }
-dontwarn androidx.**

# Remove logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

-assumenosideeffects class timber.log.Timber {
    public static void tag(java.lang.String);
    public static void d(...);
    public static void v(...);
    public static void i(...);
    public static void w(...);
    public static void e(...);
    public static void wtf(...);
}

# Native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# R8/Full Mode
-keep class * extends androidx.fragment.app.Fragment { *; }
-keep class * extends androidx.appcompat.app.AppCompatActivity { *; }

# Preserve line numbers for debugging
-keepattributes SourceFile,LineNumberTable

# Preserve names for R8/Full Mode
-keepattributes *Annotation*

# Don't note that Retrofit and OkHttp are using the api and implementation annotations
-dontnote retrofit2.**
-dontnote okhttp3.**

# Obfuscate
-repackageclasses ''
-allowaccessmodification
-dontwarn com.google.errorprone.annotations.**
-dontwarn org.slf4j.**
-keep class com.google.errorprone.annotations.** { *; }
-keep class org.slf4j.** { *; }
-keepattributes *Annotation*
-ignorewarnings
