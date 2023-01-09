// RUN: make run-test
#include "ckzg.h"
#include <stdio.h>

void calculate_proof_and_commitment(char * trusted_setup_path){
   KZGSettings *s = load_trusted_setup_wrap(trusted_setup_path);
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
   int res1 = blob_to_kzg_commitment_wrap(commitment, blob, s);

   FILE *f = fopen("output.txt", "wt");
   // commitment
   for(int i = 0; i< 48; i++){
      fprintf(f, "%02x", commitment[i]);
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
   calculate_proof_and_commitment("../../src/trusted_setup.txt");
   return 0;
}