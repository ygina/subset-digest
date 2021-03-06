#![feature(exit_status_error)]
#[macro_use]
extern crate log;

use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::net::TcpStream;
use std::io::{Read, Write, Cursor};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use hex;
use bincode;
use ssh2::Session;
use clap::{Arg, Command};
use accumulator::*;

use pcap_parser::*;
// use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;

/// Connect to the SSH server and assert the session is authenticated.
fn establish_ssh_session(
    addr: &str,
    username: &str,
    private_key_file: &str,
) -> Session {
    debug!("establishing ssh connection to {}", addr);
    let tcp = TcpStream::connect(format!("{}:22", addr)).unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_pubkey_file(
        username,
        None,
        Path::new(private_key_file),
        None,
    ).unwrap();
    assert!(sess.authenticated());
    sess
}

/// Call the accumulator's TCP service and read the bytes.
/// Assume we know which type of accumulator it is using.
/// TODO: SSH into Pi and call the TCP service from there since
/// the TCP port shouldn't be externally exposed.
fn get_accumulator(
    ssh: Option<Vec<&str>>,
    reset: bool,
    port: u32,
    ty: &str,
) -> Box<dyn Accumulator> {
    let mut buf = Vec::new();
    if let Some(ssh) = ssh {
        let sess = establish_ssh_session(ssh[0], ssh[1], ssh[2]);
        let mut channel = sess.channel_session().unwrap();
        let cmd = if reset {
            format!("echo -n -e '\\x01' | nc -v 127.0.0.1 {}", port)
        } else {
            format!("echo -n -e '\\x00' | nc -v 127.0.0.1 {}", port)
        };
        channel.exec(&cmd).unwrap();
        channel.read_to_end(&mut buf).unwrap();
        channel.wait_close().unwrap();
        let exit_status = channel.exit_status().unwrap();
        if exit_status != 0 {
            error!("channel exit status: {}", exit_status);
            panic!("error retrieving accumulator digest");
        }
    } else {
        let address = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(address).unwrap();
        stream.read_to_end(&mut buf).unwrap();
    };
    info!("accumulator size = {} bytes", buf.len());
    info!("accumulator type = {}", ty);

    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let path = format!("results/digests/{}.digest", time);
    let mut f = File::create(&path).unwrap();
    f.write_all(&buf[..]).unwrap();
    f.flush().unwrap();
    debug!("saving digest in {}", path);
    match ty {
        "naive" => Box::new(bincode::deserialize::<NaiveAccumulator>(&buf).unwrap()),
        "iblt" => {
            warn!("do IBLT parameters match the router's?");
            Box::new(IBLTAccumulator::from_bytes(
                &buf,
                DEFAULT_BITS_PER_ENTRY,
                DEFAULT_NUM_HASHES,
            ))
        },
        "power_sum" => Box::new(PowerSumAccumulator::from_bytes(&buf)),
        _ => unreachable!(),
    }
}

/// Read the file that contains the router logs.
/// - `ssh`: address and port to SSH into, if provided
/// - `filename`: name of the file, if remote make sure to specify full path
/// - `nbytes`: number of bytes per packet
/// TODO: SFTP logs from router.
fn get_router_logs(
    mut pkts_to_skip: usize,
    ssh: Option<Vec<&str>>,
    filename: &str,
    nbytes: usize,
    drop: Option<usize>
) -> Vec<Vec<u8>> {
    let t = Instant::now();
    let data: Vec<u8> = if let Some(ssh) = ssh {
        let remote_path = format!("{}@{}:{}", ssh[1], ssh[0], filename);
        let local_path = Path::new(filename).file_name().unwrap();
        std::process::Command::new("rsync")
            .arg(&remote_path)
            .arg(local_path)
            .spawn().unwrap()
            .wait().unwrap()
            .exit_ok().unwrap();
        debug!("rsynced logs from {}: {:?}", remote_path, Instant::now() - t);
        std::fs::read(local_path).unwrap()
    } else {
        if !std::path::Path::new(filename).exists() {
            panic!("file does not exist: {}", filename);
        }
        debug!("reading local logs from {}", filename);
        std::fs::read(filename).unwrap()
    };
    debug!("loaded local file: {:?}", Instant::now() - t);

    // https://docs.rs/pcap-parser/latest/pcap_parser/struct.PcapNGReader.html
    info!("parsing router logs: {} bytes", data.len());
    let mut reader = create_reader(65536, Cursor::new(data)).unwrap();
    let mut res = Vec::new();
    let mut maybe_truncated = false;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                maybe_truncated = false;
                match block {
                    PcapBlockOwned::Legacy(block) => {
                        if pkts_to_skip != 0 {
                            pkts_to_skip -= 1;
                        } else {
                            let hi = std::cmp::min(14 + nbytes, block.data.len());
                            let mut elem = block.data[14..hi].to_vec();
                            if elem.len() < nbytes {
                                elem.append(&mut vec![0; nbytes - elem.len()]);
                            }
                            res.push(elem);
                        }
                    },
                    PcapBlockOwned::NG(block) => {
                        debug!("ignoring NG({:?}) offset={}", block, offset);
                    },
                    PcapBlockOwned::LegacyHeader(_) => {},
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => {
                debug!("reached eof");
                break;
            },
            Err(PcapError::Incomplete) => {
                if maybe_truncated {
                    debug!("input file may be truncated");
                    break;
                }
                trace!("reader buffer size is too small");
                maybe_truncated = true;
                reader.refill().unwrap();
            },
            Err(e) => error!("error while reading: {:?}", e),
        }
    }
    debug!("parsed {} packets: {:?}", res.len(), Instant::now() - t);
    if let Some(drop) = drop {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..drop {
            if res.is_empty() {
                break;
            }
            let i = rng.gen_range(0..res.len());
            res.remove(i);
            debug!("removed index {}", i);
        }
    }
    res
}

/// Logs seem to have many repeated entries.
/// Maps log values to indexes at which they occur.
fn to_map(logs: &Vec<Vec<u8>>) -> HashMap<Vec<u8>, Vec<usize>> {
    let mut map: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
    for (i, entry) in logs.iter().enumerate() {
        (*map.entry(entry.clone()).or_insert(vec![])).push(i+1);
    }
    map
}

/// Compares maps to each other. Metrics include number of entries, number of
/// shared keys, and counts of shared keys.
fn compare_maps(m1: HashMap<Vec<u8>, Vec<usize>>, m2: HashMap<Vec<u8>, Vec<usize>>) {
    let mut is_subset = true;
    for (k, v2) in m2.iter() {
        if let Some(v1) = m1.get(k) {
            if v1.len() < v2.len() {
                is_subset = false;
                break;
            }
        } else {
            is_subset = false;
            break;
        }
    }
    if is_subset {
        info!("m2 is a subset of m1");
    } else {
        warn!("m2 is not a subset of m1");
    }

    if m1.len() == m2.len() {
        debug!("both maps have {} entries", m1.len());
    } else {
        debug!("# entries differs: {} != {}", m1.len(), m2.len());
    }
    let m1_keys = m1.keys().collect::<HashSet<_>>();
    let m2_keys = m2.keys().collect::<HashSet<_>>();
    let mut shared_keys: HashSet<Vec<u8>> = HashSet::new();
    let mut m1_only: HashSet<Vec<u8>> = HashSet::new();
    let mut m2_only: HashSet<Vec<u8>> = HashSet::new();
    for &k in &m1_keys {
        if !m2_keys.contains(k) {
            m1_only.insert(k.clone());
        } else {
            shared_keys.insert(k.clone());
        }
    }
    for &k in &m2_keys {
        if !m1_keys.contains(k) {
            m2_only.insert(k.clone());
        } else {
            shared_keys.insert(k.clone());
        }
    }
    debug!("{} shared keys", shared_keys.len());
    debug!("{} keys in m1 only", m1_only.len());
    debug!("{} keys in m2 only", m2_only.len());
    for k in &shared_keys {
        let m1_v = m1.get(k).unwrap();
        let m2_v = m2.get(k).unwrap();
        if m1_v.len() < m2_v.len() {
            debug!("shared key 0x{} values differ: {:?} < {:?}",
                hex::encode(k), m1_v, m2_v);
        }
    }
    // debug!("keys in m1 but not m2: {}", m1_only.len());
    // for k in m1_only {
    //     println!("0x{:X} {:?}", k, m1.get(&k).unwrap());
    // }
    debug!("keys in m2 but not m1: {}", m2_only.len());
    for k in m2_only {
        println!("0x{} {:?}", hex::encode(&k), m2.get(&k).unwrap());
    }
}

/// Check the accumulator logs against the router logs (DEBUGGING ONLY).
fn check_acc_logs(
    router_ssh: Option<Vec<&str>>,
    acc_ssh: Option<Vec<&str>>,
    drop: Option<usize>,
    router_filename: &str,
    acc_filename: &str,
    bytes: usize,
) {
    info!("router logs:");
    let router_logs = get_router_logs(
        0, router_ssh, router_filename, bytes, drop);
    let router_logs_map = to_map(&router_logs);
    for i in 0..std::cmp::min(10, router_logs.len()) {
        println!("0x{}", hex::encode(&router_logs[i]));
    }
    info!("accumulator logs:");
    let accumulator_logs = get_router_logs(
        0, acc_ssh, acc_filename, bytes, None);
    let accumulator_logs_map = to_map(&accumulator_logs);
    for i in 0..std::cmp::min(10, accumulator_logs.len()) {
        println!("0x{}", hex::encode(&accumulator_logs[i]));
    }
    compare_maps(router_logs_map, accumulator_logs_map);
}

/// Attempts to truncate as much of the log as possible such that it is still
/// a subset, assuming validation passed initially. Returns the number of
/// packets one can truncate while still being a superset of the digest.
fn check_truncation(
    accumulator: &Box<dyn Accumulator>,
    logs: &Vec<Vec<u8>>,
) -> usize {
    let mut lo = 0;
    let mut hi = logs.len() - accumulator.total();
    while lo != hi {
        let mid = (lo + hi) / 2;
        if accumulator.validate(&logs[..logs.len() - mid].to_vec()).is_valid() {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();

    let matches = Command::new("verifier")
        .arg(Arg::new("check-acc-logs")
            .help("Whether to check accumulator logs against router logs. \
                FOR DEBUGGING ONLY. (suggested: accum.pcap)")
            .long("check-acc-logs")
            .takes_value(true))
        .arg(Arg::new("port")
            .help("Port of the accumulator's TCP service.")
            .short('p')
            .long("port")
            .takes_value(true)
            .default_value("7878"))
        .arg(Arg::new("filename")
            .help("File to read router logs.")
            .short('f')
            .long("filename")
            .takes_value(true)
            .default_value("/mnt/sda1/router.pcap"))
        .arg(Arg::new("index")
            .help("Index of the log to start considering from, used when \
                the log is truncated in a previous iteration.")
            .short('i')
            .long("index")
            .takes_value(true)
            .default_value("0"))
        .arg(Arg::new("bytes")
            .help("Number of bytes recorded from each packet. Default is \
                40 bytes, enough to capture an IPv6 header.")
            .short('b')
            .long("bytes")
            .takes_value(true)
            .default_value("40"))
        .arg(Arg::new("drop")
            .help("Purposefully drop this number of packets to mimic \
                malicious packets that were not logged, hoping they were \
                not actually dropped.")
            .short('d')
            .long("drop")
            .takes_value(true))
        .arg(Arg::new("reset")
            .help("If the flag is set, resets the digest each time it is \
                serialized.")
            .long("reset"))
        .arg(Arg::new("router-ssh")
            .help("Address of the router to SSH into (if not local) i.e. \
                `openwrt.lan`, the username, and the path to the private \
                key file. Assumes port 22.")
            .long("router-ssh")
            .takes_value(true)
            .multiple_values(true)
            .number_of_values(3)
            .value_names(&["address", "username", "private_key_file"]))
        .arg(Arg::new("accumulator-ssh")
            .help("Address of the accumulator to SSH into (if not local) i.e. \
                `openwrt.lan`, the username, and the path to the private \
                key file. Assumes port 22.")
            .long("accumulator-ssh")
            .takes_value(true)
            .multiple_values(true)
            .number_of_values(3)
            .value_names(&["address", "username", "private_key_file"]))
        .arg(Arg::new("accumulator")
            .help("")
            .short('a')
            .long("accumulator")
            .takes_value(true)
            .possible_value("naive")
            .possible_value("cbf")
            .possible_value("iblt")
            .possible_value("power_sum")
            .required(true))
        .get_matches();

    let port: u32 = matches.value_of("port").unwrap().parse().unwrap();
    let filename = matches.value_of("filename").unwrap();
    let bytes: usize = matches.value_of("bytes").unwrap().parse().unwrap();
    let accumulator_type = matches.value_of("accumulator").unwrap();
    let reset = matches.is_present("reset");
    let accumulator_ssh = matches.values_of("accumulator-ssh").map(|ssh|
       ssh.collect());
    let router_ssh = matches.values_of("router-ssh").map(|ssh| ssh.collect());
    let drop: Option<usize> = matches.value_of("drop").map(|num|
        num.parse().unwrap());

    if let Some(acc_filename) = matches.value_of("check-acc-logs") {
        check_acc_logs(
            router_ssh.clone(),
            accumulator_ssh.clone(),
            drop,
            filename,
            acc_filename,
            bytes,
        )
    } else {
        let t1 = Instant::now();
        let accumulator = get_accumulator(
            accumulator_ssh,
            reset,
            port,
            accumulator_type,
        );
        let t2 = Instant::now();
        info!("get_accumulator: {:?}", t2 - t1);
        let start_index = matches.value_of("index").unwrap().parse().unwrap();
        let router_logs = get_router_logs(
            start_index,
            router_ssh,
            filename,
            bytes,
            drop,
        );
        let t3 = Instant::now();
        info!("get_router_logs: {:?}", t3 - t2);
        info!("{}/{} packets received", accumulator.total(), router_logs.len());
        assert!(accumulator.total() <= router_logs.len());
        let valid = accumulator.validate(&router_logs).is_valid();
        if valid {
            info!("valid router");
        } else {
            warn!("invalid router");
        }
        let t4 = Instant::now();
        info!("validation: {:?}", t4 - t3);
        info!("TOTAL VERIFICATION TIME: {:?}", t4 - t1);

        if valid {
            let num_truncated = check_truncation(&accumulator, &router_logs);
            let t5 = Instant::now();
            info!("truncated {}/{} packets: {:?}", num_truncated,
                router_logs.len(), t5 - t4);
            let num_dropped = router_logs.len() - accumulator.total() -
                num_truncated;
            info!("probably dropped {} packets", num_dropped);
            info!("received {} packets", accumulator.total());
            info!("next start index would be {}, or {} if conservative",
                start_index + router_logs.len() - num_truncated,
                start_index + accumulator.total());
        }
    }
}
