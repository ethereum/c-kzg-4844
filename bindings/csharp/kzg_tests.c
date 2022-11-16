
// RUN: make run-test
#include "ckzg.h"
#include <stdio.h>

void TestProofs(char * path){
   KZGSettings *s = load_trusted_setup_wrap(path);
   size_t n = 1;
   uint8_t *commitment = (uint8_t *)calloc(48, 1);
   uint8_t *proof = (uint8_t *)calloc(48, 1);
   uint8_t *blob = (uint8_t *)calloc(4096, 32);
   uint8_t *blobHash = (uint8_t *)calloc(32, 1);
   n = 0;
   for(int i = 0; i < 5875; i++){
      if((n + 1) % 32 == 0)n++;
      blob[n] = i % 250;
      n++;
   }
   int res0 = compute_aggregate_kzg_proof_wrap(proof, blob, 1, s);
   blob_to_kzg_commitment_wrap(commitment, blob, s);

   // commitment
   FILE *f = fopen("output.txt", "wt");
   for(int i = 0; i< 4096*32; i++){
      fprintf(f, "%02x", blob[i]);
   }
   fprintf(f, "\n");
   
   for(int i = 0; i< 48; i++){
      fprintf(f, "%02x", commitment[i]);
   }
   fprintf(f, "\n");

   // hash
   hash(blobHash, commitment, 48);
   blobHash[0] = 1;
   for(int i = 0; i< 32; i++){
      fprintf(f, "%02x", blobHash[i]);
   }
   fprintf(f, "\n");

   // proof
   for(int i = 0; i< 48; i++){
      fprintf(f, "%02x", proof[i]);
   }
   fprintf(f, "\n");

   fclose(f);
   free(blob);
   free(commitment);
   free(proof); 
   free_trusted_setup_wrap(s);
}


int main() {
   TestProofs("devnetv2-geth.txt");
   return 0;
}