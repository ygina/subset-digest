#[macro_use]
extern crate log;

use rand;
use rand::Rng;
use std::time::Instant;
use clap::{Arg, Command};
use accumulator::*;

const BATCH_UNIT: u32 = 1000;

struct MockAccumulator {}
impl Accumulator for MockAccumulator {
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
    fn reset(&mut self) {
    }
    fn process(&mut self, _elem: &[u8]) {
    }
    fn process_batch(&mut self, _elems: &Vec<Vec<u8>>) {
        unimplemented!()
    }
    fn total(&self) -> usize {
        unimplemented!()
    }
    fn validate(&self, _elems: &Vec<Vec<u8>>) -> ValidationResult {
        unimplemented!()
    }
}

fn gen_accumulator(
    ty: &str,
    threshold: usize,
    iblt_params: Option<Vec<&str>>,
) -> Box<dyn Accumulator> {
    match ty {
        "mock" => Box::new(MockAccumulator {}),
        "naive" => Box::new(NaiveAccumulator::new(None)),
        "iblt" => {
            let params = iblt_params.unwrap();
            Box::new(IBLTAccumulator::new_with_params(
                threshold,
                params[0].parse().unwrap(),
                params[1].parse().unwrap(),
                params[2].parse().unwrap(),
                None,
            ))
        },
        "psum" => Box::new(PowerSumAccumulator::new(threshold, None)),
        _ => unreachable!(),
    }
}

fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();
    let matches = Command::new("benchmark-overhead")
        .arg(Arg::new("n")
            .help("Number of packets.")
            .short('n')
            .takes_value(true)
            .default_value("1000"))
        .arg(Arg::new("bytes")
            .help("Number of bytes per packet.")
            .short('n')
            .long("bytes")
            .takes_value(true)
            .default_value("24"))
        .arg(Arg::new("trials")
            .help("Number of trials per accumulator.")
            .long("trials")
            .takes_value(true)
            .default_value("21"))
        .arg(Arg::new("threshold")
            .help("Threshold number of dropped packets for the IBLT and power \
                sum accumulators.")
            .short('t')
            .long("threshold")
            .takes_value(true)
            .default_value("1000"))
        .arg(Arg::new("iblt-params")
            .help("IBLT parameters.")
            .long("iblt-params")
            .value_names(&["bits_per_entry", "cells_multiplier", "num_hashes"])
            .takes_value(true)
            .number_of_values(3)
            .required_if_eq("accumulator", "iblt")
            .default_values(&["8", "10", "2"]))
        .arg(Arg::new("accumulator")
            .help("Accumulator to benchmark. If none are passed, runs them
               all.")
            .short('a')
            .long("accumulator")
            .takes_value(true)
            .possible_value("mock")
            .possible_value("naive")
            .possible_value("iblt")
            .possible_value("psum"))
        .get_matches();

    let n: usize = matches.value_of_t("n").unwrap();
    let b: usize = matches.value_of_t("bytes").unwrap();
    let t: usize = matches.value_of_t("threshold").unwrap();
    let trials: usize = matches.value_of_t("trials").unwrap();
    let iblt_params: Option<Vec<&str>> = matches.values_of("iblt-params")
        .map(|params| params.collect());
    let tys = if let Some(ty) = matches.value_of("accumulator") {
        vec![ty]
    } else {
        vec!["mock", "naive", "iblt", "psum"]
    };
    let mut accs: Vec<_> = tys.iter()
        .map(|ty| gen_accumulator(ty, t, iblt_params.clone()))
        .collect();

    // Generate elements.
    let mut rng = rand::thread_rng();
    let elems: Vec<Vec<u8>> = (0..n)
        .map(|_| (0..b).map(|_| rng.gen::<u8>()).collect::<Vec<_>>())
        .collect();
    info!("per {} packets", BATCH_UNIT);
    for i in 0..tys.len() {
        let mut totals = vec![];
        for _ in 0..trials {
            let now = Instant::now();
            for elem in &elems {
                accs[i].process(elem);
            }
            let total = Instant::now() - now;
            totals.push(BATCH_UNIT * total / (n as u32))
        }
        totals.sort();
        info!(
            "{}\t{:?}",
            tys[i],
            totals[totals.len() / 2],
        );
    }
}
