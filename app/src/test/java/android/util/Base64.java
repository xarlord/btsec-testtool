/*
 * Stub for android.util.Base64 to allow JVM unit tests.
 * Delegates to java.util.Base64.
 */
package android.util;

public class Base64 {
    public static final int DEFAULT = 0;
    public static final int NO_WRAP = 2;
    public static final int CRLF = 4;
    public static final int NO_PADDING = 1;
    public static final int URL_SAFE = 8;
    public static final int NO_CLOSE = 16;

    public static byte[] decode(String str, int flags) {
        if (str == null) return null;
        java.util.Base64.Decoder decoder = (flags & URL_SAFE) != 0
            ? java.util.Base64.getUrlDecoder()
            : java.util.Base64.getMimeDecoder();
        return decoder.decode(str);
    }

    public static byte[] decode(byte[] input, int flags) {
        if (input == null) return null;
        java.util.Base64.Decoder decoder = (flags & URL_SAFE) != 0
            ? java.util.Base64.getUrlDecoder()
            : java.util.Base64.getMimeDecoder();
        return decoder.decode(input);
    }

    public static String encodeToString(byte[] input, int flags) {
        if (input == null) return null;
        java.util.Base64.Encoder encoder = (flags & URL_SAFE) != 0
            ? ((flags & NO_PADDING) != 0 ? java.util.Base64.getUrlEncoder().withoutPadding() : java.util.Base64.getUrlEncoder())
            : ((flags & NO_PADDING) != 0 ? java.util.Base64.getMimeEncoder().withoutPadding() : java.util.Base64.getMimeEncoder());
        return encoder.encodeToString(input);
    }

    public static byte[] encode(byte[] input, int flags) {
        if (input == null) return null;
        java.util.Base64.Encoder encoder = (flags & URL_SAFE) != 0
            ? ((flags & NO_PADDING) != 0 ? java.util.Base64.getUrlEncoder().withoutPadding() : java.util.Base64.getUrlEncoder())
            : ((flags & NO_PADDING) != 0 ? java.util.Base64.getMimeEncoder().withoutPadding() : java.util.Base64.getMimeEncoder());
        return encoder.encode(input);
    }
}
