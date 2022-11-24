import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class CKzg4844JNI {

  private final static String LIBRARY_NAME = "ckzg4844jni";
  private final static String PLATFORM_NATIVE_LIBRARY_NAME = System.mapLibraryName(LIBRARY_NAME);

  static {
    InputStream libraryResource = CKzg4844JNI.class.getResourceAsStream(
        "lib/" + PLATFORM_NATIVE_LIBRARY_NAME);
    if (libraryResource == null) {
      try {
        System.loadLibrary(LIBRARY_NAME);
      } catch (UnsatisfiedLinkError ex) {
        throw new RuntimeException(ex);
      }
    } else {
      try {
        Path tmpdir = Files.createTempDirectory(LIBRARY_NAME + "@");
        tmpdir.toFile().deleteOnExit();
        Path tmpdll = tmpdir.resolve(PLATFORM_NATIVE_LIBRARY_NAME);
        tmpdll.toFile().deleteOnExit();
        Files.copy(libraryResource, tmpdll, StandardCopyOption.REPLACE_EXISTING);
        libraryResource.close();
        System.load(tmpdll.toString());
      } catch (IOException ex) {
        throw new RuntimeException(ex);
      }
    }
  }

  public static int BYTES_PER_COMMITMENT = 48;
  public static int BYTES_PER_PROOF = 48;
  public static int FIELD_ELEMENTS_PER_BLOB = 4096;
  public static int BYTES_PER_FIELD_ELEMENT = 32;
  public static int BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

  public static native void loadTrustedSetup(String file);

  public static native void freeTrustedSetup();

  public static native byte[] computeAggregateKzgProof(byte[] blobs, long count);

  public static native boolean verifyAggregateKzgProof(byte[] blobs, byte[] commitments, long count,
      byte[] proof);

  public static native byte[] blobToKzgCommitment(byte[] blob);

  public static native boolean verifyKzgProof(byte[] commitment, byte[] z, byte[] y, byte[] proof);

}
