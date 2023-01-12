use std::path::PathBuf;

use c_kzg::*;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::ThreadRng, Rng};
use std::sync::Arc;

fn generate_random_blob_for_bench(rng: &mut ThreadRng) -> Blob {
    let mut arr: Blob = [0; BYTES_PER_BLOB];
    rng.fill(&mut arr[..]);
    // Ensure that the blob is canonical by ensuring that
    // each field element contained in the blob is < BLS_MODULUS
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        arr[i * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT - 1] = 0;
    }
    arr
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
    assert!(trusted_setup_file.exists());
    let kzg_settings = Arc::new(KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap());

    let blob = generate_random_blob_for_bench(&mut rng);
    c.bench_function("blob_to_kzg_commitment", |b| {
        b.iter(|| KzgCommitment::blob_to_kzg_commitment(blob, &kzg_settings))
    });

    for num_blobs in [4, 8, 16].iter() {
        let mut group = c.benchmark_group("kzg operations");

        let blobs: Vec<Blob> = (0..*num_blobs)
            .map(|_| generate_random_blob_for_bench(&mut rng))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("compute_aggregate_kzg_proof", *num_blobs),
            &blobs,
            |b, blobs| b.iter(|| KzgProof::compute_aggregate_kzg_proof(blobs, &kzg_settings)),
        );

        let kzg_commitments: Vec<KzgCommitment> = blobs
            .clone()
            .into_iter()
            .map(|blob| KzgCommitment::blob_to_kzg_commitment(blob, &kzg_settings))
            .collect();
        let proof = KzgProof::compute_aggregate_kzg_proof(&blobs, &kzg_settings).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_aggregate_kzg_proof", *num_blobs),
            &blobs,
            |b, blobs| {
                b.iter(|| {
                    proof
                        .verify_aggregate_kzg_proof(&blobs, &kzg_commitments, &kzg_settings)
                        .unwrap()
                })
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
