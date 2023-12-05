#include <stdio.h>
#include <stdlib.h>
#include <string.h> // For memcpy
#include "c_kzg_4844_jni.h"
#include "c_kzg_4844.h"

static const char *TRUSTED_SETUP_NOT_LOADED = "Trusted Setup is not loaded.";

KZGSettings *settings;

void reset_trusted_setup(void)
{
  if (settings)
  {
    free_trusted_setup(settings);
    free(settings);
    settings = NULL;
  }
}

void throw_exception(JNIEnv *env, const char *message)
{
  jclass exception_class = (*env)->FindClass(env, "java/lang/RuntimeException");
  (*env)->ThrowNew(env, exception_class, message);
}

void throw_c_kzg_exception(JNIEnv *env, C_KZG_RET error_code, const char *message)
{
  jclass exception_class = (*env)->FindClass(env, "ethereum/ckzg4844/CKZGException");
  jstring error_message = (*env)->NewStringUTF(env, message);
  jmethodID exception_constructor = (*env)->GetMethodID(env, exception_class, "<init>", "(ILjava/lang/String;)V");
  jobject exception = (*env)->NewObject(env, exception_class, exception_constructor, error_code, error_message);
  (*env)->Throw(env, exception);
}

void throw_invalid_size_exception(JNIEnv *env, const char *prefix, size_t size, size_t expected_size)
{
  char message[100];
  snprintf(message, sizeof(message), "%s Expected %zu bytes but got %zu.", prefix, expected_size, size);
  throw_c_kzg_exception(env, C_KZG_BADARGS, message);
}

KZGSettings *allocate_settings(JNIEnv *env)
{
  KZGSettings *s = malloc(sizeof(KZGSettings));
  if (s == NULL)
  {
    throw_exception(env, "Failed to allocate memory for the Trusted Setup.");
  }
  else
  {
    s->max_width = 0;
    s->roots_of_unity = NULL;
    s->g1_values = NULL;
    s->g2_values = NULL;
  }
  return s;
}

JNIEXPORT void JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_loadTrustedSetup__Ljava_lang_String_2(JNIEnv *env, jclass thisCls, jstring file)
{
  if (settings)
  {
    throw_exception(env, "Trusted Setup is already loaded. Free it before loading a new one.");
    return;
  }

  settings = allocate_settings(env);

  const char *file_native = (*env)->GetStringUTFChars(env, file, 0);

  FILE *f = fopen(file_native, "r");

  if (f == NULL)
  {
    reset_trusted_setup();
    (*env)->ReleaseStringUTFChars(env, file, file_native);
    throw_exception(env, "Couldn't load Trusted Setup. File might not exist or there is a permission issue.");
    return;
  }

  C_KZG_RET ret = load_trusted_setup_file(settings, f);

  (*env)->ReleaseStringUTFChars(env, file, file_native);
  fclose(f);

  if (ret != C_KZG_OK)
  {
    reset_trusted_setup();
    throw_c_kzg_exception(env, ret, "There was an error while loading the Trusted Setup.");
    return;
  }
}

JNIEXPORT void JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_loadTrustedSetup___3BJ_3BJ(JNIEnv *env, jclass thisCls, jbyteArray g1, jlong g1Count, jbyteArray g2, jlong g2Count)
{
  if (settings)
  {
    throw_exception(env, "Trusted Setup is already loaded. Free it before loading a new one.");
    return;
  }

  size_t g1_bytes = (size_t)(*env)->GetArrayLength(env, g1);
  size_t g1_expected_bytes = (size_t)g1Count * 48;

  if (g1_bytes != g1_expected_bytes)
  {
    throw_invalid_size_exception(env, "Invalid g1 size.", g1_bytes, g1_expected_bytes);
    return;
  }

  size_t g2_bytes = (size_t)(*env)->GetArrayLength(env, g2);
  size_t g2_expected_bytes = (size_t)g2Count * 96;

  if (g2_bytes != g2_expected_bytes)
  {
    throw_invalid_size_exception(env, "Invalid g2 size.", g2_bytes, g2_expected_bytes);
    return;
  }

  settings = allocate_settings(env);

  jbyte *g1_native = (*env)->GetByteArrayElements(env, g1, NULL);
  jbyte *g2_native = (*env)->GetByteArrayElements(env, g2, NULL);

  C_KZG_RET ret = load_trusted_setup(settings, (uint8_t *)g1_native, (size_t)g1Count, (uint8_t *)g2_native, (size_t)g2Count);

  (*env)->ReleaseByteArrayElements(env, g1, g1_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, g2, g2_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    reset_trusted_setup();
    throw_c_kzg_exception(env, ret, "There was an error while loading the Trusted Setup.");
    return;
  }
}

JNIEXPORT void JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_freeTrustedSetup(JNIEnv *env, jclass thisCls)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return;
  }
  reset_trusted_setup();
}

JNIEXPORT jbyteArray JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray blob)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  size_t blob_size = (size_t)(*env)->GetArrayLength(env, blob);
  if (blob_size != BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blob size.", blob_size, BYTES_PER_BLOB);
    return NULL;
  }

  jbyte *blob_native = (*env)->GetByteArrayElements(env, blob, NULL);
  jbyteArray commitment = (*env)->NewByteArray(env, BYTES_PER_COMMITMENT);
  KZGCommitment *commitment_native = (KZGCommitment *)(*env)->GetByteArrayElements(env, commitment, NULL);

  C_KZG_RET ret = blob_to_kzg_commitment(commitment_native, (const Blob *)blob_native, settings);

  (*env)->ReleaseByteArrayElements(env, blob, blob_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, commitment, (jbyte *)commitment_native, 0);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in blobToKzgCommitment.");
    return NULL;
  }

  return commitment;
}

JNIEXPORT jobject JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_computeKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blob, jbyteArray z_bytes)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  size_t blob_size = (size_t)(*env)->GetArrayLength(env, blob);
  if (blob_size != BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blob size.", blob_size, BYTES_PER_BLOB);
    return NULL;
  }

  size_t z_bytes_size = (size_t)(*env)->GetArrayLength(env, z_bytes);
  if (z_bytes_size != BYTES_PER_FIELD_ELEMENT)
  {
    throw_invalid_size_exception(env, "Invalid z size.", z_bytes_size, BYTES_PER_FIELD_ELEMENT);
    return NULL;
  }

  /* The output variables, will be combined in a ProofAndY object */
  jbyteArray proof = (*env)->NewByteArray(env, BYTES_PER_PROOF);
  jbyteArray y = (*env)->NewByteArray(env, BYTES_PER_FIELD_ELEMENT);

  /* The native variables */
  KZGProof *proof_native = (KZGProof *)(uint8_t *)(*env)->GetByteArrayElements(env, proof, NULL);
  Bytes32 *y_native = (Bytes32 *)(uint8_t *)(*env)->GetByteArrayElements(env, y, NULL);
  Blob *blob_native = (Blob *)(*env)->GetByteArrayElements(env, blob, NULL);
  Bytes32 *z_native = (Bytes32 *)(*env)->GetByteArrayElements(env, z_bytes, NULL);

  C_KZG_RET ret = compute_kzg_proof(proof_native, y_native, blob_native, z_native, settings);

  (*env)->ReleaseByteArrayElements(env, proof, (jbyte *)proof_native, 0);
  (*env)->ReleaseByteArrayElements(env, y, (jbyte *)y_native, 0);
  (*env)->ReleaseByteArrayElements(env, blob, (jbyte *)blob_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, z_bytes, (jbyte *)z_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in computeKzgProof.");
    return NULL;
  }

  jclass proof_and_y_class = (*env)->FindClass(env, "ethereum/ckzg4844/ProofAndY");
  if (proof_and_y_class == NULL)
  {
    throw_exception(env, "Failed to find ProofAndY class.");
    return NULL;
  }

  jmethodID proof_and_y_constructor = (*env)->GetMethodID(env, proof_and_y_class, "<init>", "([B[B)V");
  if (proof_and_y_constructor == NULL)
  {
    throw_exception(env, "Failed to find ProofAndY constructor.");
    return NULL;
  }

  jobject proof_and_y = (*env)->NewObject(env, proof_and_y_class, proof_and_y_constructor, proof, y);
  if (proof_and_y == NULL)
  {
    throw_exception(env, "Failed to instantiate new ProofAndY.");
    return NULL;
  }

  return proof_and_y;
}

JNIEXPORT jbyteArray JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_computeBlobKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blob, jbyteArray commitment_bytes)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  size_t blob_size = (size_t)(*env)->GetArrayLength(env, blob);
  if (blob_size != BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blob size.", blob_size, BYTES_PER_BLOB);
    return NULL;
  }

  size_t commitment_bytes_size = (size_t)(*env)->GetArrayLength(env, commitment_bytes);
  if (commitment_bytes_size != BYTES_PER_COMMITMENT)
  {
    throw_invalid_size_exception(env, "Invalid commitment size.", commitment_bytes_size, BYTES_PER_COMMITMENT);
    return NULL;
  }

  Blob *blob_native = (Blob *)(*env)->GetByteArrayElements(env, blob, NULL);
  Bytes48 *commitment_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitment_bytes, NULL);

  jbyteArray proof = (*env)->NewByteArray(env, BYTES_PER_PROOF);
  KZGProof *proof_native = (KZGProof *)(uint8_t *)(*env)->GetByteArrayElements(env, proof, NULL);

  C_KZG_RET ret = compute_blob_kzg_proof(proof_native, blob_native, commitment_native, settings);

  (*env)->ReleaseByteArrayElements(env, blob, (jbyte *)blob_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, commitment_bytes, (jbyte *)commitment_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, proof, (jbyte *)proof_native, 0);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in computeBlobKzgProof.");
    return NULL;
  }

  return proof;
}

JNIEXPORT jboolean JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment_bytes, jbyteArray z_bytes, jbyteArray y_bytes, jbyteArray proof_bytes)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  size_t commitment_bytes_size = (size_t)(*env)->GetArrayLength(env, commitment_bytes);
  if (commitment_bytes_size != BYTES_PER_COMMITMENT)
  {
    throw_invalid_size_exception(env, "Invalid commitment size.", commitment_bytes_size, BYTES_PER_COMMITMENT);
    return 0;
  }

  size_t z_bytes_size = (size_t)(*env)->GetArrayLength(env, z_bytes);
  if (z_bytes_size != BYTES_PER_FIELD_ELEMENT)
  {
    throw_invalid_size_exception(env, "Invalid z size.", z_bytes_size, BYTES_PER_FIELD_ELEMENT);
    return 0;
  }

  size_t y_bytes_size = (size_t)(*env)->GetArrayLength(env, y_bytes);
  if (y_bytes_size != BYTES_PER_FIELD_ELEMENT)
  {
    throw_invalid_size_exception(env, "Invalid y size.", y_bytes_size, BYTES_PER_FIELD_ELEMENT);
    return 0;
  }

  size_t proof_bytes_size = (size_t)(*env)->GetArrayLength(env, proof_bytes);
  if (proof_bytes_size != BYTES_PER_PROOF)
  {
    throw_invalid_size_exception(env, "Invalid proof size.", proof_bytes_size, BYTES_PER_PROOF);
    return 0;
  }

  Bytes48 *commitment_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitment_bytes, NULL);
  Bytes48 *proof_native = (Bytes48 *)(*env)->GetByteArrayElements(env, proof_bytes, NULL);
  Bytes32 *z_native = (Bytes32 *)(*env)->GetByteArrayElements(env, z_bytes, NULL);
  Bytes32 *y_native = (Bytes32 *)(*env)->GetByteArrayElements(env, y_bytes, NULL);

  bool out;
  C_KZG_RET ret = verify_kzg_proof(&out, commitment_native, z_native, y_native, proof_native, settings);

  (*env)->ReleaseByteArrayElements(env, commitment_bytes, (jbyte *)commitment_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, z_bytes, (jbyte *)z_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, y_bytes, (jbyte *)y_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, proof_bytes, (jbyte *)proof_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in verifyKzgProof.");
    return 0;
  }

  return (jboolean)out;
}

JNIEXPORT jboolean JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blob, jbyteArray commitment_bytes, jbyteArray proof_bytes)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  size_t blob_size = (size_t)(*env)->GetArrayLength(env, blob);
  if (blob_size != BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blob size.", blob_size, BYTES_PER_BLOB);
    return 0;
  }

  size_t commitment_bytes_size = (size_t)(*env)->GetArrayLength(env, commitment_bytes);
  if (commitment_bytes_size != BYTES_PER_COMMITMENT)
  {
    throw_invalid_size_exception(env, "Invalid commitment size.", commitment_bytes_size, BYTES_PER_COMMITMENT);
    return 0;
  }

  size_t proof_bytes_size = (size_t)(*env)->GetArrayLength(env, proof_bytes);
  if (proof_bytes_size != BYTES_PER_PROOF)
  {
    throw_invalid_size_exception(env, "Invalid proof size.", proof_bytes_size, BYTES_PER_PROOF);
    return 0;
  }

  Blob *blob_native = (Blob *)(*env)->GetByteArrayElements(env, blob, NULL);
  Bytes48 *commitment_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitment_bytes, NULL);
  Bytes48 *proof_native = (Bytes48 *)(*env)->GetByteArrayElements(env, proof_bytes, NULL);

  bool out;
  C_KZG_RET ret = verify_blob_kzg_proof(&out, blob_native, commitment_native, proof_native, settings);

  (*env)->ReleaseByteArrayElements(env, blob, (jbyte *)blob_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, commitment_bytes, (jbyte *)commitment_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, proof_bytes, (jbyte *)proof_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in verifyBlobKzgProof.");
    return 0;
  }

  return (jboolean)out;
}

JNIEXPORT jboolean JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments_bytes, jbyteArray proofs_bytes, jlong count)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  size_t count_native = (size_t)count;
  size_t blobs_size = (size_t)(*env)->GetArrayLength(env, blobs);
  if (blobs_size != count_native * BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blobs size.", blobs_size, count_native * BYTES_PER_BLOB);
    return 0;
  }

  size_t commitments_bytes_size = (size_t)(*env)->GetArrayLength(env, commitments_bytes);
  if (commitments_bytes_size != count_native * BYTES_PER_COMMITMENT)
  {
    throw_invalid_size_exception(env, "Invalid commitments size.", commitments_bytes_size, count_native * BYTES_PER_COMMITMENT);
    return 0;
  }

  size_t proofs_bytes_size = (size_t)(*env)->GetArrayLength(env, proofs_bytes);
  if (proofs_bytes_size != count_native * BYTES_PER_PROOF)
  {
    throw_invalid_size_exception(env, "Invalid proofs size.", proofs_bytes_size, count_native * BYTES_PER_PROOF);
    return 0;
  }

  Blob *blobs_native = (Blob *)(*env)->GetByteArrayElements(env, blobs, NULL);
  Bytes48 *commitments_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitments_bytes, NULL);
  Bytes48 *proofs_native = (Bytes48 *)(*env)->GetByteArrayElements(env, proofs_bytes, NULL);

  bool out;
  C_KZG_RET ret = verify_blob_kzg_proof_batch(&out, blobs_native, commitments_native, proofs_native, count_native, settings);

  (*env)->ReleaseByteArrayElements(env, blobs, (jbyte *)blobs_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, commitments_bytes, (jbyte *)commitments_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, proofs_bytes, (jbyte *)proofs_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in verifyBlobKzgProofBatch.");
    return 0;
  }

  return (jboolean)out;
}

JNIEXPORT jobjectArray JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_getSamples(JNIEnv *env, jclass thisCls, jbyteArray blob, jint row_index)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  size_t blob_size = (size_t)(*env)->GetArrayLength(env, blob);
  if (blob_size != BYTES_PER_BLOB)
  {
    throw_invalid_size_exception(env, "Invalid blob size.", blob_size, BYTES_PER_BLOB);
    return NULL;
  }

  /* The output variables, will be combined in a Sample object */
  jbyteArray samples = (*env)->NewByteArray(env, SAMPLES_PER_BLOB * sizeof(Sample));

  /* The native variables */
  Sample *samples_native = (Sample *)(*env)->GetByteArrayElements(env, samples, NULL);
  Blob *blob_native = (Blob *)(*env)->GetByteArrayElements(env, blob, NULL);
  uint32_t row_index_native = (uint32_t)row_index;

  C_KZG_RET ret = get_samples(samples_native, blob_native, row_index_native, settings);

  (*env)->ReleaseByteArrayElements(env, samples, (jbyte *)samples_native, 0);
  (*env)->ReleaseByteArrayElements(env, blob, (jbyte *)blob_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in getSamples.");
    return NULL;
  }

  jclass sample_class = (*env)->FindClass(env, "ethereum/ckzg4844/Sample");
  if (sample_class == NULL)
  {
    throw_exception(env, "Failed to find Sample class.");
    return NULL;
  }

  jmethodID sample_of = (*env)->GetStaticMethodID(env, sample_class, "of", "([B)[Lethereum/ckzg4844/Sample;");
  if (sample_of == NULL)
  {
    throw_exception(env, "Failed to find Sample#of method.");
    return NULL;
  }

  jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, sample_class, sample_of, samples);
  if (result == NULL)
  {
    throw_exception(env, "Failed to instantiate samples.");
    return NULL;
  }

  return result;
}

JNIEXPORT jbyteArray JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_samplesToBlob(JNIEnv *env, jclass thisCls, jobjectArray samples)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  if (samples == NULL)
  {
    throw_exception(env, "Array of samples is null.");
    return NULL;
  }

  size_t count = (size_t)(*env)->GetArrayLength(env, samples);
  if (count != SAMPLES_PER_BLOB)
  {
    throw_exception(env, "Invalid number of samples.");
    return NULL;
  }

  jobject sample_obj = (*env)->GetObjectArrayElement(env, samples, 0);
  if (sample_obj == NULL)
  {
    throw_exception(env, "Sample is null.");
    return NULL;
  }

  jclass sample_class = (*env)->GetObjectClass(env, sample_obj);
  jmethodID to_bytes_method = (*env)->GetMethodID(env, sample_class, "toBytes", "()[B");
  if (to_bytes_method == NULL)
  {
    throw_exception(env, "Failed to find toBytes method");
    return NULL;
  }

  jbyteArray all_samples = (*env)->NewByteArray(env, count * BYTES_PER_SAMPLE);
  Sample *all_samples_native = (Sample *)(*env)->GetByteArrayElements(env, all_samples, NULL);

  for (size_t i = 0; i < count; i++)
  {
    jobject sample = (*env)->GetObjectArrayElement(env, samples, i);
    if (sample == NULL)
    {
      throw_exception(env, "Sample is null.");
      return NULL;
    }

    jbyteArray sample_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sample, to_bytes_method);
    if ((*env)->ExceptionCheck(env))
    {
        return NULL;
    }

    Sample *sample_native = (Sample *)(*env)->GetByteArrayElements(env, sample_bytes, NULL);
    memcpy(&all_samples_native[i], sample_native, sizeof(Sample));
    (*env)->ReleaseByteArrayElements(env, sample_bytes, (jbyte *)sample_native, 0);
  }

  jbyteArray blob = (*env)->NewByteArray(env, BYTES_PER_BLOB);
  Blob *blob_native = (Blob *)(*env)->GetByteArrayElements(env, blob, NULL);

  C_KZG_RET ret = samples_to_blob(blob_native, all_samples_native);

  (*env)->DeleteLocalRef(env, sample_obj);
  (*env)->DeleteLocalRef(env, sample_class);
  (*env)->ReleaseByteArrayElements(env, blob, (jbyte *)blob_native, 0);
  (*env)->ReleaseByteArrayElements(env, all_samples, (jbyte *)all_samples_native, JNI_ABORT);
  (*env)->DeleteLocalRef(env, all_samples);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in samplesToBlob.");
    return NULL;
  }

  return blob;
}

JNIEXPORT jobjectArray JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_recoverSamples(JNIEnv *env, jclass thisCls, jobjectArray samples)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return NULL;
  }

  if (samples == NULL)
  {
    throw_exception(env, "Array of samples is null.");
    return NULL;
  }

  size_t count = (size_t)(*env)->GetArrayLength(env, samples);
  if (count == 0)
  {
    throw_exception(env, "Invalid number of samples.");
    return NULL;
  }

  jobject sample_obj = (*env)->GetObjectArrayElement(env, samples, 0);
  if (sample_obj == NULL)
  {
    throw_exception(env, "Sample is null.");
    return NULL;
  }

  jclass sample_class = (*env)->GetObjectClass(env, sample_obj);
  jmethodID to_bytes_method = (*env)->GetMethodID(env, sample_class, "toBytes", "()[B");
  if (to_bytes_method == NULL)
  {
    throw_exception(env, "Failed to find toBytes method");
    return NULL;
  }

  jbyteArray all_samples = (*env)->NewByteArray(env, count * BYTES_PER_SAMPLE);
  Sample *all_samples_native = (Sample *)(*env)->GetByteArrayElements(env, all_samples, NULL);

  for (size_t i = 0; i < count; i++)
  {
    jobject sample = (*env)->GetObjectArrayElement(env, samples, i);
    if (sample == NULL)
    {
      throw_exception(env, "Sample is null.");
      return NULL;
    }

    jbyteArray sample_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sample, to_bytes_method);
    if ((*env)->ExceptionCheck(env))
    {
        return NULL;
    }

    Sample *sample_native = (Sample *)(*env)->GetByteArrayElements(env, sample_bytes, NULL);
    memcpy(&all_samples_native[i], sample_native, sizeof(Sample));
    (*env)->ReleaseByteArrayElements(env, sample_bytes, (jbyte *)sample_native, 0);
  }

  jbyteArray recovered = (*env)->NewByteArray(env, SAMPLES_PER_BLOB * sizeof(Sample));
  Sample *recovered_native = (Sample *)(*env)->GetByteArrayElements(env, recovered, NULL);
  size_t count_native = (size_t)count;

  C_KZG_RET ret = recover_samples(recovered_native, all_samples_native, count_native, settings);

  (*env)->DeleteLocalRef(env, sample_obj);
  (*env)->ReleaseByteArrayElements(env, recovered, (jbyte *)recovered_native, 0);
  (*env)->ReleaseByteArrayElements(env, all_samples, (jbyte *)all_samples_native, JNI_ABORT);
  (*env)->DeleteLocalRef(env, all_samples);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in samplesToBlob.");
    return NULL;
  }

  jmethodID sample_of = (*env)->GetStaticMethodID(env, sample_class, "of", "([B)[Lethereum/ckzg4844/Sample;");
  if (sample_of == NULL)
  {
    throw_exception(env, "Failed to find Sample#of method.");
    return NULL;
  }

  jobjectArray result = (jobjectArray)(*env)->CallStaticObjectMethod(env, sample_class, sample_of, recovered);
  if (result == NULL)
  {
    throw_exception(env, "Failed to instantiate samples.");
    return NULL;
  }

  (*env)->DeleteLocalRef(env, sample_class);

  return result;
}

JNIEXPORT jboolean JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_verifySample(JNIEnv *env, jclass thisCls, jbyteArray commitment_bytes, jobject sample)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  jclass sample_class = (*env)->GetObjectClass(env, sample);

  jmethodID to_bytes_method = (*env)->GetMethodID(env, sample_class, "toBytes", "()[B");
  if (to_bytes_method == NULL)
  {
    throw_exception(env, "Failed to find toBytes method");
    return 0;
  }
  jbyteArray sample_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sample, to_bytes_method);

  Sample *sample_native = (Sample *)(*env)->GetByteArrayElements(env, sample_bytes, NULL);
  Bytes48 *commitment_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitment_bytes, NULL);

  bool out;
  C_KZG_RET ret = verify_sample(&out, commitment_native, sample_native, settings);

  (*env)->DeleteLocalRef(env, sample_class);
  (*env)->ReleaseByteArrayElements(env, sample_bytes, (jbyte *)sample_native, 0);
  (*env)->ReleaseByteArrayElements(env, commitment_bytes, (jbyte *)commitment_native, JNI_ABORT);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in verifySample.");
    return 0;
  }

  return (jboolean)out;
}

JNIEXPORT jboolean JNICALL Java_ethereum_ckzg4844_CKZG4844JNI_verifySamples(JNIEnv *env, jclass thisCls, jbyteArray commitments_bytes, jobjectArray samples)
{
  if (settings == NULL)
  {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  if (samples == NULL)
  {
    throw_exception(env, "Array of samples is null.");
    return 0;
  }

  size_t count = (size_t)(*env)->GetArrayLength(env, samples);
  if (count == 0)
  {
    return 1;
  }

  jobject sample_obj = (*env)->GetObjectArrayElement(env, samples, 0);
  if (sample_obj == NULL)
  {
    throw_exception(env, "Sample is null.");
    return 0;
  }

  jclass sample_class = (*env)->GetObjectClass(env, sample_obj);
  jmethodID to_bytes_method = (*env)->GetMethodID(env, sample_class, "toBytes", "()[B");
  if (to_bytes_method == NULL)
  {
    throw_exception(env, "Failed to find toBytes method");
    return 0;
  }

  jbyteArray all_samples = (*env)->NewByteArray(env, count * BYTES_PER_SAMPLE);
  Sample *all_samples_native = (Sample *)(*env)->GetByteArrayElements(env, all_samples, NULL);

  for (size_t i = 0; i < count; i++)
  {
    jobject sample = (*env)->GetObjectArrayElement(env, samples, i);
    if (sample == NULL)
    {
      throw_exception(env, "Sample is null.");
      return 0;
    }

    jbyteArray sample_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sample, to_bytes_method);
    if ((*env)->ExceptionCheck(env))
    {
        return 0;
    }

    Sample *sample_native = (Sample *)(*env)->GetByteArrayElements(env, sample_bytes, NULL);
    memcpy(&all_samples_native[i], sample_native, sizeof(Sample));
    (*env)->ReleaseByteArrayElements(env, sample_bytes, (jbyte *)sample_native, 0);
  }

  Bytes48 *commitments_native = (Bytes48 *)(*env)->GetByteArrayElements(env, commitments_bytes, NULL);
  size_t num_commitments = (size_t)(*env)->GetArrayLength(env, commitments_bytes) / BYTES_PER_COMMITMENT;

  bool out;
  C_KZG_RET ret = verify_samples(&out, commitments_native, num_commitments, all_samples_native, count, settings);

  (*env)->DeleteLocalRef(env, sample_obj);
  (*env)->DeleteLocalRef(env, sample_class);
  (*env)->ReleaseByteArrayElements(env, commitments_bytes, (jbyte *)commitments_native, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, all_samples, (jbyte *)all_samples_native, JNI_ABORT);
  (*env)->DeleteLocalRef(env, all_samples);

  if (ret != C_KZG_OK)
  {
    throw_c_kzg_exception(env, ret, "There was an error in verifySamples.");
    return 0;
  }

  return (jboolean)out;
}
