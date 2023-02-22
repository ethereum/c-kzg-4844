use std::path::PathBuf;

use c_kzg::*;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::ThreadRng, Rng};
use std::sync::Arc;

fn generate_random_field_element(rng: &mut ThreadRng) -> Bytes32 {
    let mut arr = [0u8; BYTES_PER_FIELD_ELEMENT];
    rng.fill(&mut arr[..]);
    arr[BYTES_PER_FIELD_ELEMENT - 1] = 0;
    arr.into()
}

fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
    let mut arr = [0u8; BYTES_PER_BLOB];
    rng.fill(&mut arr[..]);
    // Ensure that the blob is canonical by ensuring that
    // each field element contained in the blob is < BLS_MODULUS
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        arr[i * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT - 1] = 0;
    }
    arr.into()
}

fn generate_random_commitment(rng: &mut ThreadRng, s: &KZGSettings) -> Bytes48 {
    let blob = generate_random_blob(rng);
    KZGCommitment::blob_to_kzg_commitment(blob, s)
        .unwrap()
        .to_bytes()
}

fn generate_random_proof(rng: &mut ThreadRng, s: &KZGSettings) -> Bytes48 {
    let blob = generate_random_blob(rng);
    KZGProof::compute_blob_kzg_proof(blob, s)
        .unwrap()
        .to_bytes()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let max_count: usize = 64;
    let mut rng = rand::thread_rng();
    let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
    assert!(trusted_setup_file.exists());
    let kzg_settings = Arc::new(KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap());

    let blobs: Vec<Blob> = (0..max_count)
        .map(|_| generate_random_blob(&mut rng))
        .collect();
    let commitments: Vec<Bytes48> = (0..max_count)
        .map(|_| generate_random_commitment(&mut rng, &kzg_settings))
        .collect();
    let proofs: Vec<Bytes48> = (0..max_count)
        .map(|_| generate_random_proof(&mut rng, &kzg_settings))
        .collect();
    let fields: Vec<Bytes32> = (0..max_count)
        .map(|_| generate_random_field_element(&mut rng))
        .collect();

    c.bench_function("blob_to_kzg_commitment", |b| {
        b.iter(|| KZGCommitment::blob_to_kzg_commitment(*blobs.first().unwrap(), &kzg_settings))
    });

    c.bench_function("compute_kzg_proof", |b| {
        b.iter(|| {
            KZGProof::compute_kzg_proof(
                *blobs.first().unwrap(),
                *fields.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    c.bench_function("compute_blob_kzg_proof", |b| {
        b.iter(|| KZGProof::compute_blob_kzg_proof(*blobs.first().unwrap(), &kzg_settings))
    });

    c.bench_function("verify_blob_kzg_proof", |b| {
        b.iter(|| {
            KZGProof::verify_blob_kzg_proof(
                *blobs.first().unwrap(),
                *commitments.first().unwrap(),
                *proofs.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    let mut group = c.benchmark_group("verify_blob_kzg_proof_batch");
    for count in [1, 2, 4, 8, 16, 32, 64] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                KZGProof::verify_blob_kzg_proof_batch(
                    &blobs.clone().into_iter().take(count).collect::<Vec<Blob>>(),
                    &commitments
                        .clone()
                        .into_iter()
                        .take(count)
                        .collect::<Vec<Bytes48>>(),
                    &proofs
                        .clone()
                        .into_iter()
                        .take(count)
                        .collect::<Vec<Bytes48>>(),
                    &kzg_settings,
                ).unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
