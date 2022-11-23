#include <stdio.h>
#include <stdlib.h>
#include "c_kzg_4844_jni.h"
#include "c_kzg_4844.h"

static const char *C_KZG_RETURN_TYPES[] = {
    "C_KZG_OK", "C_KZG_BADARGS", "C_KZG_ERROR", "C_KZG_MALLOC"};

KZGSettings *settings;

void reset_trusted_setup()
{
  free(settings);
  settings = NULL;
}

void throw_exception(JNIEnv *env, const char *message)
{
  jclass Exception = (*env)->FindClass(env, "java/lang/RuntimeException");
  (*env)->ThrowNew(env, Exception, message);
}

void verify_trusted_setup_is_loaded(JNIEnv *env)
{
  if (settings == NULL)
  {
    throw_exception(env, "Trusted Setup is not loaded.");
  }
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_loadTrustedSetup(JNIEnv *env, jclass thisCls, jstring file)
{
  settings = malloc(sizeof(KZGSettings));

  const char *file_native = (*env)->GetStringUTFChars(env, file, 0);

  FILE *f = fopen(file_native, "r");

  if (f == NULL)
  {
    reset_trusted_setup();
    (*env)->ReleaseStringUTFChars(env, file, file_native);
    throw_exception(env, "Couldn't load Trusted Setup. File might not exist or there is a permission issue.");
    return;
  }

  C_KZG_RET ret = load_trusted_setup(settings, f);

  if (ret != C_KZG_OK)
  {
    reset_trusted_setup();
    (*env)->ReleaseStringUTFChars(env, file, file_native);
    fclose(f);
    char arr[60];
    sprintf(arr, "There was an error while loading the Trusted Setup: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return;
  }

  fclose(f);

  printf("Loaded Trusted Setup from %s\n", file_native);

  (*env)->ReleaseStringUTFChars(env, file, file_native);
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_freeTrustedSetup(JNIEnv *env, jclass thisCls)
{
  verify_trusted_setup_is_loaded(env);
  free_trusted_setup(settings);
  reset_trusted_setup();
  printf("Trusted Setup was unloaded\n");
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_computeAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jint count)
{
  verify_trusted_setup_is_loaded(env);
  // NOT YET IMPLEMENTED
  // jbyte *blobs_native = (*env)->GetByteArrayElements(env, blobs, NULL);
  jbyteArray proof = (*env)->NewByteArray(env, 48);
  return proof;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments, jint count, jbyteArray proof)
{
  verify_trusted_setup_is_loaded(env);
  // NOT YET IMPLEMENTED
  return false;
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray blob)
{
  verify_trusted_setup_is_loaded(env);
  // NOT YET IMPLEMENTED
  jbyteArray ret = (*env)->NewByteArray(env, 48);
  return ret;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment, jbyteArray z, jbyteArray y, jbyteArray proof)
{
  verify_trusted_setup_is_loaded(env);
  // NOT YET IMPLEMENTED
  return false;
}
