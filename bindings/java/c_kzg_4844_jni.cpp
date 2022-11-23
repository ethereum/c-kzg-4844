#include "c_kzg_4844_jni.h"
#include "c_kzg_4844.h"

KZGSettings *settings;

JNIEXPORT void JNICALL Java_CKzg4844JNI_loadTrustedSetup(JNIEnv *env, jclass thisCls, jstring file)
{
  settings = malloc(sizeof(KZGSettings));

  const char *file_native = env->GetStringUTFChars(file, 0);

  FILE *f = fopen(file_native, "r");

  if (f == NULL)
  {
    free(settings);
    env->ReleaseStringUTFChars(file, file_native);
    // need to throw an exception
    return;
  }

  if (load_trusted_setup(settings, f) != C_KZG_OK)
  {
    free(settings);
    fclose(f);
    env->ReleaseStringUTFChars(file, file_native);
    // need to throw an exception
    return;
  }

  fclose(f);
  env->ReleaseStringUTFChars(file, file_native);
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_freeTrustedSetup(JNIEnv *env, jclass thisCls)
{
  free_trusted_setup(settings);
  free(settings);
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_computeAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jint count)
{
  jbyte *blobs_native = env->GetByteArrayElements(blobs, NULL);
  jbyteArray proof = env->NewByteArray(48);
  g1_t *out;
  bytes_to_g1(out, (uint8_t *)blobs_native);
  return proof;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments, jint count, jbyteArray proof)
{
  return false;
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray commitment)
{
  jbyteArray ret = env->NewByteArray(48);
  return ret;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment, jbyteArray z, jbyteArray y, jbyteArray proof)
{
  return false;
}
