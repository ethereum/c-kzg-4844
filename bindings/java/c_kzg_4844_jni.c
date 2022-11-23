#include <stdlib.h>
#include "c_kzg_4844_jni.h"
#include "c_kzg_4844.h"

KZGSettings *settings;

JNIEXPORT void JNICALL Java_CKzg4844JNI_loadTrustedSetup(JNIEnv *env, jclass thisCls, jstring file)
{
  settings = malloc(sizeof(KZGSettings));

  const char *file_native = (*env)->GetStringUTFChars(env, file, 0);

  FILE *f = fopen(file_native, "r");

  if (f == NULL)
  {
    free(settings);
    (*env)->ReleaseStringUTFChars(env, file, file_native);
    return;
  }

  if (load_trusted_setup(settings, f) != C_KZG_OK)
  {
    free(settings);
    fclose(f);
    (*env)->ReleaseStringUTFChars(env, file, file_native);
    return;
  }

  fclose(f);

  printf("Loaded Trusted Setup from %s\n", file_native);

  (*env)->ReleaseStringUTFChars(env, file, file_native);
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_freeTrustedSetup(JNIEnv *env, jclass thisCls)
{
  free_trusted_setup(settings);
  free(settings);
  printf("Trusted Setup was unloaded\n");
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_computeAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jint count)
{
  // NOT YET IMPLEMENTED
  // jbyte *blobs_native = (*env)->GetByteArrayElements(env, blobs, NULL);
  jbyteArray proof = (*env)->NewByteArray(env, 48);
  return proof;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments, jint count, jbyteArray proof)
{
  // NOT YET IMPLEMENTED
  return false;
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray blob)
{
  // NOT YET IMPLEMENTED
  jbyteArray ret = (*env)->NewByteArray(env, 48);
  return ret;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment, jbyteArray z, jbyteArray y, jbyteArray proof)
{
  // NOT YET IMPLEMENTED
  return false;
}
