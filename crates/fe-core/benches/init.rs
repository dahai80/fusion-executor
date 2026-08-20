use criterion::{criterion_group, criterion_main, Criterion};
use fe_core::Executor;

fn bench_init(c: &mut Criterion) {
    c.bench_function("Executor::new", |b| {
        b.iter(|| {
            let ex = Executor::new();
            std::hint::black_box(&ex);
        });
    });
}

criterion_group!(benches, bench_init);
criterion_main!(benches);
