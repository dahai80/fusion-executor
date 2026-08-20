use criterion::{criterion_group, criterion_main, Criterion};
use fe_sandbox::truncate_output;

fn bench_truncation(c: &mut Criterion) {
    let mut group = c.benchmark_group("truncate_output");
    for &size in &[100_000usize, 1_000_000, 10_000_000] {
        let big = "x".repeat(size);
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_with_input(format!("size_{size}"), &big, |b, s| {
            b.iter(|| truncate_output(s, 100_000));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_truncation);
criterion_main!(benches);
