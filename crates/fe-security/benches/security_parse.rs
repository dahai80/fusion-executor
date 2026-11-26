use criterion::{criterion_group, criterion_main, Criterion};
use fe_security::SecurityGuard;

fn bench_security_parse(c: &mut Criterion) {
    let guard = SecurityGuard::new();
    let simple = "echo hi && ls -la && cat foo.txt && grep bar baz.txt";
    // 10k-char compound command — chain-bypass defense NFR
    let big = "echo ok && pytest tests/ && ".repeat(500) + "rm -rf /";
    c.bench_function("validate_simple_compound", |b| {
        b.iter(|| guard.validate(std::hint::black_box(simple)));
    });
    c.bench_function("validate_10k_compound", |b| {
        b.iter(|| guard.validate(std::hint::black_box(&big)));
    });
}

criterion_group!(benches, bench_security_parse);
criterion_main!(benches);
