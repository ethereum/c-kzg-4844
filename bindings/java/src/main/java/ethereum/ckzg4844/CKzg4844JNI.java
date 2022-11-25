package ethereum.ckzg4844;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class CKzg4844JNI {

  private static final String LIBRARY_NAME = "ckzg4844jni";
  private static final String PLATFORM_NATIVE_LIBRARY_NAME = System.mapLibraryName(LIBRARY_NAME);

  static {
    InputStream libraryResource = Thread.currentThread().getContextClassLoader()
        .getResourceAsStream(
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

  /**
   * Loads the trusted setup from a file. Once loaded, the same setup will be used for all the
   * native calls. To load a new setup, free the current one by calling {@link #freeTrustedSetup()}
   * and then load the new one. If no trusted setup has been loaded, all the native calls will throw
   * an exception.
   *
   * @param file A path to a trusted setup file
   */
  public static native void loadTrustedSetup(String file);

  /**
   * Free the current trusted setup. This method will throw an exception if no trusted setup has
   * been loaded.
   */
  public static native void freeTrustedSetup();

  /**
   * Calculates aggregated proof for the given blobs
   *
   * @param blobs blobs as flattened bytes
   * @param count the count of the blobs
   * @return the aggregated proof
   */
  public static native byte[] computeAggregateKzgProof(byte[] blobs, long count);

  /**
   * Verify aggregated proof and commitments for the given blobs
   *
   * @param blobs       blobs as flattened bytes
   * @param commitments commitments as flattened bytes
   * @param count       the count of the blobs (should be same as the count of the commitments)
   * @param proof       the proof that needs verifying
   * @return true if the proof is valid and false otherwise
   */
  public static native boolean verifyAggregateKzgProof(byte[] blobs, byte[] commitments, long count,
      byte[] proof);

  /**
   * Calculates commitment for a given blob
   *
   * @param blob blob bytes
   * @return the commitment
   */
  public static native byte[] blobToKzgCommitment(byte[] blob);

  /**
   * Verify the proof by point evaluation for the given commitment
   *
   * @param commitment commitment bytes
   * @param z          Z
   * @param y          Y
   * @param proof      the proof that needs verifying
   * @return true if the proof is valid and false otherwise
   */
  public static native boolean verifyKzgProof(byte[] commitment, byte[] z, byte[] y, byte[] proof);

}
