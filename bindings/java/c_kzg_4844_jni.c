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

bool verify_trusted_setup_is_loaded(JNIEnv *env)
{
  if (settings == NULL)
  {
    throw_exception(env, "Trusted Setup is not loaded.");
    return false;
  }
  return true;
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_loadTrustedSetup(JNIEnv *env, jclass thisCls, jstring file)
{
  if (settings != NULL)
  {
    throw_exception(env, "Trusted Setup is already loaded. Free it before loading a new one.");
    return;
  }
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
  if (!verify_trusted_setup_is_loaded(env))
  {
    return;
  }
  free_trusted_setup(settings);
  reset_trusted_setup();
  printf("Trusted Setup was freed\n");
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_computeAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jlong count)
{
  if (!verify_trusted_setup_is_loaded(env))
  {
    return NULL;
  }

  jbyte *blobs_native = (*env)->GetByteArrayElements(env, blobs, NULL);

  KZGProof p;

  C_KZG_RET ret = compute_aggregate_kzg_proof(&p, (uint8_t const(*)[BYTES_PER_BLOB])blobs_native, (size_t)count, settings);

  if (ret != C_KZG_OK)
  {
    char arr[60];
    sprintf(arr, "There was an error while computing aggregate kzg proof: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return NULL;
  }

  jbyteArray proof = (*env)->NewByteArray(env, BYTES_PER_PROOF);
  uint8_t *out = (uint8_t *)(*env)->GetByteArrayElements(env, proof, 0);

  bytes_from_g1(out, &p);

  (*env)->ReleaseByteArrayElements(env, proof, (jbyte *)out, 0);

  return proof;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments, jlong count, jbyteArray proof)
{
  if (!verify_trusted_setup_is_loaded(env))
  {
    return 0;
  }

  jbyte *blobs_native = (*env)->GetByteArrayElements(env, blobs, NULL);
  uint8_t *commitments_native = (uint8_t *)(*env)->GetByteArrayElements(env, commitments, NULL);
  uint8_t *proof_native = (uint8_t *)(*env)->GetByteArrayElements(env, proof, NULL);
  size_t native_count = (size_t)count;

  KZGProof f;

  C_KZG_RET ret;

  ret = bytes_to_g1(&f, proof_native);

  if (ret != C_KZG_OK)
  {
    char arr[60];
    sprintf(arr, "There was an error while converting proof bytes to g1: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return 0;
  }

  KZGCommitment *c = calloc(native_count, sizeof(KZGCommitment));

  for (size_t i = 0; i < native_count; i++)
  {
    ret = bytes_to_g1(&c[i], &commitments_native[i * BYTES_PER_COMMITMENT]);
    if (ret != C_KZG_OK)
    {
      free(c);
      char arr[60];
      sprintf(arr, "There was an error while converting commitment (%zu/%zu) bytes to g1: %s", i + 1, native_count, C_KZG_RETURN_TYPES[ret]);
      throw_exception(env, arr);
      return 0;
    }
  }

  bool out;
  ret = verify_aggregate_kzg_proof(&out, (uint8_t const(*)[BYTES_PER_BLOB])blobs_native, c, native_count, &f, settings);

  if (ret != C_KZG_OK)
  {
    free(c);
    char arr[60];
    sprintf(arr, "There was an error while verifying aggregate kzg proof: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return 0;
  }

  free(c);

  return (jboolean)out;
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray blob)
{
  if (!verify_trusted_setup_is_loaded(env))
  {
    return NULL;
  }

  uint8_t *blob_native = (uint8_t *)(*env)->GetByteArrayElements(env, blob, NULL);

  KZGCommitment c;
  blob_to_kzg_commitment(&c, blob_native, settings);

  jbyteArray commitment = (*env)->NewByteArray(env, BYTES_PER_COMMITMENT);
  uint8_t *out = (uint8_t *)(*env)->GetByteArrayElements(env, commitment, 0);

  bytes_from_g1(out, &c);

  (*env)->ReleaseByteArrayElements(env, commitment, (jbyte *)out, 0);

  return commitment;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment, jbyteArray z, jbyteArray y, jbyteArray proof)
{
  if (!verify_trusted_setup_is_loaded(env))
  {
    return 0;
  }

  uint8_t *commitment_native = (uint8_t *)(*env)->GetByteArrayElements(env, commitment, NULL);
  uint8_t *z_native = (uint8_t *)(*env)->GetByteArrayElements(env, z, NULL);
  uint8_t *y_native = (uint8_t *)(*env)->GetByteArrayElements(env, y, NULL);
  uint8_t *proof_native = (uint8_t *)(*env)->GetByteArrayElements(env, proof, NULL);

  KZGCommitment c;
  KZGProof p;
  bool out;

  C_KZG_RET ret;

  ret = bytes_to_g1(&c, commitment_native);

  if (ret != C_KZG_OK)
  {
    char arr[60];
    sprintf(arr, "There was an error while converting commitment bytes to g1: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return 0;
  }

  ret = bytes_to_g1(&p, proof_native);

  if (ret != C_KZG_OK)
  {
    char arr[60];
    sprintf(arr, "There was an error while converting proof bytes to g1: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return 0;
  }

  ret = verify_kzg_proof(&out, &c, z_native, y_native, &p, settings);

  if (ret != C_KZG_OK)
  {
    char arr[60];
    sprintf(arr, "There was an error while verifying kzg proof: %s", C_KZG_RETURN_TYPES[ret]);
    throw_exception(env, arr);
    return 0;
  }

  return (jboolean)out;
}
