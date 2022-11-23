#include "c_kzg_4844_jni.h"
#include "c_kzg_4844.h"

JNIEXPORT jobject JNICALL Java_CKzg4844JNI_loadTrustedSetup(JNIEnv *env, jclass thisCls, jstring file)
{
  return NULL;
}

JNIEXPORT void JNICALL Java_CKzg4844JNI_freeTrustedSetup(JNIEnv *env, jclass thisCls, jobject settings)
{
  // NO-OP
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_computeAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jint count, jobject settings)
{
  jbyte *blobs_c = (*env)->GetByteArrayElements(env, blobs, NULL);
  jbyteArray proof = (*env)->NewByteArray(env, 48);
  g1_t *out;
  bytes_to_g1(out, (uint8_t *)blobs_c);
  return proof;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyAggregateKzgProof(JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments, jint count, jbyteArray proof, jobject settings)
{
  return false;
}

JNIEXPORT jbyteArray JNICALL Java_CKzg4844JNI_blobToKzgCommitment(JNIEnv *env, jclass thisCls, jbyteArray commitment, jobject settings)
{
  jbyteArray ret = (*env)->NewByteArray(env, 48);
  return ret;
}

JNIEXPORT jboolean JNICALL Java_CKzg4844JNI_verifyKzgProof(JNIEnv *env, jclass thisCls, jbyteArray commitment, jbyteArray z, jbyteArray y, jbyteArray proof, jobject settings)
{
  return false;
}
