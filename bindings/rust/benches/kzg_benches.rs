use c_kzg::*;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rand::{rngs::ThreadRng, Rng};
use std::path::Path;
use std::sync::Arc;

fn generate_random_field_element(rng: &mut ThreadRng) -> Bytes32 {
    let mut arr = [0u8; BYTES_PER_FIELD_ELEMENT];
    rng.fill(&mut arr[..]);
    arr[0] = 0;
    arr.into()
}

fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
    let mut arr = [0u8; BYTES_PER_BLOB];
    rng.fill(&mut arr[..]);
    // Ensure that the blob is canonical by ensuring that
    // each field element contained in the blob is < BLS_MODULUS
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        arr[i * BYTES_PER_FIELD_ELEMENT] = 0;
    }
    arr.into()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let max_count: usize = 64;
    let mut rng = rand::thread_rng();
    let trusted_setup_file = Path::new("src/trusted_setup.txt");
    assert!(trusted_setup_file.exists());
    let kzg_settings = Arc::new(KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap());

    let blobs: Vec<Blob> = (0..max_count)
        .map(|_| generate_random_blob(&mut rng))
        .collect();
    let commitments: Vec<Bytes48> = blobs
        .iter()
        .map(|blob| {
            KzgCommitment::blob_to_kzg_commitment(blob, &kzg_settings)
                .unwrap()
                .to_bytes()
        })
        .collect();
    let proofs: Vec<Bytes48> = blobs
        .iter()
        .zip(commitments.iter())
        .map(|(blob, commitment)| {
            KzgProof::compute_blob_kzg_proof(blob, commitment, &kzg_settings)
                .unwrap()
                .to_bytes()
        })
        .collect();
    let fields: Vec<Bytes32> = (0..max_count)
        .map(|_| generate_random_field_element(&mut rng))
        .collect();

    c.bench_function("blob_to_kzg_commitment", |b| {
        b.iter(|| KzgCommitment::blob_to_kzg_commitment(&blobs[0], &kzg_settings))
    });

    c.bench_function("compute_kzg_proof", |b| {
        b.iter(|| KzgProof::compute_kzg_proof(&blobs[0], &fields[0], &kzg_settings))
    });

    c.bench_function("compute_blob_kzg_proof", |b| {
        b.iter(|| KzgProof::compute_blob_kzg_proof(&blobs[0], &commitments[0], &kzg_settings))
    });

    c.bench_function("verify_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::verify_kzg_proof(
                &commitments[0],
                &fields[0],
                &fields[0],
                &proofs[0],
                &kzg_settings,
            )
        })
    });

    c.bench_function("verify_blob_kzg_proof", |b| {
        b.iter(|| {
            KzgProof::verify_blob_kzg_proof(&blobs[0], &commitments[0], &proofs[0], &kzg_settings)
        })
    });

    let mut group = c.benchmark_group("verify_blob_kzg_proof_batch");
    for count in [1, 2, 4, 8, 16, 32, 64] {
        assert!(count <= max_count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched_ref(
                || {
                    let blobs_subset = blobs[..count].to_vec();
                    let commitments_subset = commitments[..count].to_vec();
                    let proofs_subset = proofs[..count].to_vec();
                    (blobs_subset, commitments_subset, proofs_subset)
                },
                |(blobs_subset, commitments_subset, proofs_subset)| {
                    KzgProof::verify_blob_kzg_proof_batch(
                        blobs_subset,
                        commitments_subset,
                        proofs_subset,
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
