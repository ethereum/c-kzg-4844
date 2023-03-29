use std::path::PathBuf;

use c_kzg::*;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
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

pub fn criterion_benchmark(c: &mut Criterion) {
    let max_count: usize = 64;
    let mut rng = rand::thread_rng();
    let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
    assert!(trusted_setup_file.exists());
    let kzg_settings = Arc::new(KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap());

    let blobs: Vec<Blob> = (0..max_count)
        .map(|_| generate_random_blob(&mut rng))
        .collect();
    let commitments: Vec<Bytes48> = blobs
        .iter()
        .map(|blob| {
            KzgCommitment::blob_to_kzg_commitment(blob.clone(), &kzg_settings)
                .unwrap()
                .to_bytes()
        })
        .collect();
    let proofs: Vec<Bytes48> = blobs
        .iter()
        .zip(commitments.iter())
        .map(|(blob, commitment)| {
            KzgProof::compute_blob_kzg_proof(blob.clone(), *commitment, &kzg_settings)
                .unwrap()
                .to_bytes()
        })
        .collect();
    let fields: Vec<Bytes32> = (0..max_count)
        .map(|_| generate_random_field_element(&mut rng))
        .collect();

    c.bench_function("blob_to_kzg_commitment", |b| {
        b.iter(|| {
            KzgCommitment::blob_to_kzg_commitment(blobs.first().unwrap().clone(), &kzg_settings)
        })
    });

    c.bench_function("compute_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::compute_kzg_proof(
                blobs.first().unwrap().clone(),
                *fields.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    c.bench_function("compute_blob_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::compute_blob_kzg_proof(
                blobs.first().unwrap().clone(),
                *commitments.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    c.bench_function("verify_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::verify_kzg_proof(
                *commitments.first().unwrap(),
                *fields.first().unwrap(),
                *fields.first().unwrap(),
                *proofs.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    c.bench_function("verify_blob_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::verify_blob_kzg_proof(
                blobs.first().unwrap().clone(),
                *commitments.first().unwrap(),
                *proofs.first().unwrap(),
                &kzg_settings,
            )
        })
    });

    let mut group = c.benchmark_group("verify_blob_kzg_proof_batch");
    for count in [1, 2, 4, 8, 16, 32, 64] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched_ref(
                || {
                    let blobs_subset = blobs.clone().into_iter().take(count).collect::<Vec<Blob>>();
                    let commitments_subset = commitments
                        .clone()
                        .into_iter()
                        .take(count)
                        .collect::<Vec<Bytes48>>();
                    let proofs_subset = proofs
                        .clone()
                        .into_iter()
                        .take(count)
                        .collect::<Vec<Bytes48>>();

                    (blobs_subset, commitments_subset, proofs_subset)
                },
                |(blobs_subset, commitments_subset, proofs_subset)| {
                    KzgProof::verify_blob_kzg_proof_batch(
                        &blobs_subset,
                        &commitments_subset,
                        &proofs_subset,
                        &kzg_settings,
                    )
                    .unwrap();
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
