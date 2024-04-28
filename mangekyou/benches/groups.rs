// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod group_benches {
    use criterion::measurement::Measurement;
    use criterion::{measurement, BenchmarkGroup, BenchmarkId, Criterion};
    use mangekyou::groups::multiplier::windowed::WindowedScalarMultiplier;
    use mangekyou::groups::multiplier::ScalarMultiplier;
    use mangekyou::groups::ristretto255::RistrettoPoint;
    use mangekyou::groups::{
        FromTrustedByteArray, GroupElement, HashToGroupElement, MultiScalarMul, Pairing,
        Scalar,
    };
    use mangekyou::serde_helpers::ToFromByteArray;
    use rand::thread_rng;

    fn add_single<G: GroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::generator() * G::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| x + y));
    }

    fn add(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Add");
        add_single::<RistrettoPoint, _>("Ristretto255", &mut group);
    }

    fn scale_single<G: GroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| x * y));
    }

    fn scale_single_precomputed<
        G: GroupElement,
        Mul: ScalarMultiplier<G, G::ScalarType>,
        M: Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(x, G::zero());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| multiplier.mul(&y)));
    }

    fn scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Scalar To Point Multiplication");
        scale_single::<RistrettoPoint, _>("Ristretto255", &mut group);
    }

    fn blst_msm_single<G: GroupElement + MultiScalarMul, M: Measurement>(
        name: &str,
        len: &usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let (scalars, points): (Vec<G::ScalarType>, Vec<G>) = (0..*len)
            .map(|_| {
                (
                    G::ScalarType::generator() * G::ScalarType::rand(&mut thread_rng()),
                    G::generator() * G::ScalarType::rand(&mut thread_rng()),
                )
            })
            .unzip();
        c.bench_function(BenchmarkId::new(name.to_string(), len), move |b| {
            b.iter(|| G::multi_scalar_mul(&scalars, &points).unwrap())
        });
    }

    fn double_scale_single<
        G: GroupElement,
        Mul: ScalarMultiplier<G, G::ScalarType>,
        M: Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let g1 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s1 = G::ScalarType::rand(&mut thread_rng());
        let g2 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s2 = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(g1, G::zero());
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| multiplier.two_scalar_mul(&s1, &g2, &s2))
        });
    }

    fn hash_to_group_single<G: GroupElement + HashToGroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let seed = b"Hello, World!";
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| G::hash_to_group_element(seed))
        });
    }

    fn hash_to_group(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Hash-to-group");
        hash_to_group_single::<RistrettoPoint, _>("Ristretto255", &mut group);
    }

    fn pairing_single<G: GroupElement + Pairing, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::Other::generator()
            * <<G as Pairing>::Other as GroupElement>::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| G::pairing(&x, &y)));
    }

    /// Implementation of a `Multiplier` where scalar multiplication is done without any pre-computation by
    /// simply calling the GroupElement implementation. Only used for benchmarking.
    struct DefaultMultiplier<G: GroupElement>(G);

    impl<G: GroupElement> ScalarMultiplier<G, G::ScalarType> for DefaultMultiplier<G> {
        fn new(base_element: G, _zero: G) -> Self {
            Self(base_element)
        }

        fn mul(&self, scalar: &G::ScalarType) -> G {
            self.0 * scalar
        }

        fn two_scalar_mul(
            &self,
            base_scalar: &G::ScalarType,
            other_element: &G,
            other_scalar: &G::ScalarType,
        ) -> G {
            self.0 * base_scalar + *other_element * other_scalar
        }
    }

    fn deser_single<
        G: GroupElement + ToFromByteArray<LENGTH> + FromTrustedByteArray<LENGTH>,
        M: Measurement,
        const LENGTH: usize,
    >(
        name: &str,
        trusted: bool,
        c: &mut BenchmarkGroup<M>,
    ) {
        let as_bytes = G::generator().to_byte_array();
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| {
                if trusted {
                    G::from_trusted_byte_array(&as_bytes).unwrap()
                } else {
                    G::from_byte_array(&as_bytes).unwrap()
                }
            })
        });
    }

    criterion_group! {
        name = group_benches;
        config = Criterion::default().sample_size(100);
        targets =
            add,
            scale,
            hash_to_group,
    }
}

criterion_main!(group_benches::group_benches,);
