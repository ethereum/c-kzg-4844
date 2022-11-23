public class CKzg4844JNI {

    public static int BYTES_PER_COMMITMENT = 48;
    public static int BYTES_PER_PROOF = 48;
    public static int FIELD_ELEMENTS_PER_BLOB = 4096;
    public static int BYTES_PER_FIELD_ELEMENT = 32;
    public static int BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

    static {
        try {
            System.loadLibrary("ckzg4844jni");
        } catch (UnsatisfiedLinkError ex) {
            throw new RuntimeException(ex);
        }
    }

    public static native void loadTrustedSetup(String file);

    public static native void freeTrustedSetup();

    public static native byte[] computeAggregateKzgProof(byte[] blobs, int count);

    public static native boolean verifyAggregateKzgProof(byte[] blobs, byte[] commitments, int count,
            byte[] proof);

    public static native byte[] blobToKzgCommitment(byte[] blob);

    public static native boolean verifyKzgProof(byte[] commitment, byte[] z, byte[] y, byte[] proof);

}
