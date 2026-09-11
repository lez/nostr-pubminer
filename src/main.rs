use std::{env, sync::mpsc::channel, sync::mpsc::Sender, fs::File, fs::OpenOptions, io::Write, thread::sleep, time::Duration};
use bech32::{ToBase32, Variant};
use secp256k1::{KeyPair, XOnlyPublicKey};

fn run_thread(sender: Sender<KeyPair>) {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::rngs::OsRng::default();
    loop {
        let secret_key = secp256k1::SecretKey::new(&mut rng);
        sender.send(KeyPair::from_secret_key(&secp, &secret_key)).unwrap();
    }
}

fn filter_pubkeys(pubkey: &str, filter: &str) -> bool {
    pubkey.starts_with(filter)
}

fn to_npub(pubkey: &XOnlyPublicKey) -> String {
    //Shamefully stolen from https://github.com/grunch/rana/blob/main/src/main.rs in order to add bech32 support
    bech32::encode(
        "npub",
        hex::decode(pubkey.to_string()).unwrap().to_base32(),
        Variant::Bech32,
    ).unwrap()
}

fn main() {
    if env::args().len() < 3 {
        println!("Usage: {} <filter> <threadAmount> <optional:hex>", env::args().nth(0).unwrap());
        println!("\t Benchmark with \"benchmark\" as filter and threadAmount as the amount of iterations");
        return;
    }
    let filter_string = env::args().nth(1).unwrap();
    let thread_amount = env::args().nth(2).unwrap().parse::<u32>().unwrap();
    let mut bech32 = true;
    if env::args().len() == 4 {
        let mode = env::args().nth(3).unwrap();
        if mode != "hex" {
            eprintln!("Invalid third parameter: '{}'. Expected 'hex' to disable bech32 mode.", mode);
            std::process::exit(1);
        }
        bech32 = false;
    }

    if filter_string == "benchmark" {
        run_benchmark(thread_amount as u128, bech32);
        return;
    }

    if bech32 {
        const BECH32_CHARSET: &str = "023456789acdefghjklmnpqrstuvwxyz";
        if let Some(invalid_char) = filter_string.chars().find(|c| !BECH32_CHARSET.contains(*c)) {
            eprintln!("Invalid bech32 character in filter: '{}'. Allowed characters: {}", invalid_char, BECH32_CHARSET);
            std::process::exit(1);
        }
    }

    println!("Thread amount: {}", thread_amount);
    let (sender, receiver) = channel();
    let mut senders: Vec<Sender<KeyPair>> = Vec::new();
    for _ in 1..thread_amount {
        senders.push(sender.clone());
    }
    senders.insert(0, sender);
    
    //Create the threads and run them
    let mut threads = Vec::new();
    for i in 0..thread_amount {
        println!("Starting thread {}", i);
        let new_sender = senders.pop().unwrap();
        threads.push(std::thread::spawn(move || {
            run_thread(new_sender);
        }));
    }

    let mut output_file: File;
    match File::open("output.csv") {
        Ok(_) => {
            output_file = OpenOptions::new().write(true).append(true).open("output.csv").unwrap();
        },
        Err(_) => {
            output_file = File::create("output.csv").unwrap();
        }
    }
    //Get the results and write them
    loop {
        let new_result = receiver.recv();
        match new_result {
            Ok(result) => {
                let (pubkey_readable, _) = XOnlyPublicKey::from_keypair(&result);
                let mut bech_key: Option<String> = None;
                if !bech32 {
                    if !filter_pubkeys(&pubkey_readable.to_string(), filter_string.as_str()) {
                        continue;
                    }
                }
                else {
                    //Convert to bech32
                    let encoded_key = to_npub(&pubkey_readable);
                    let new_filter_string = format!("npub1{}", filter_string);
                    if !filter_pubkeys(&encoded_key, new_filter_string.as_str()) {
                        continue;
                    }
                    bech_key = Some(encoded_key);
                }
                let bech_key = bech_key.unwrap_or_else(|| to_npub(&pubkey_readable));

                let tmp_output = format!("{};{};{}\n", bech_key, result.display_secret(), pubkey_readable);
                println!("{}", bech_key);
                output_file.write_all(tmp_output.as_bytes()).unwrap();
            },
            Err(_) => {
                sleep(Duration::from_secs(1));
            }
        }
        
    }
}

fn run_benchmark(amount_of_tries: u128, bech32: bool) {
    let (sender, receiver) = channel();
        use std::time::Instant;
        let filter_string = String::from("impossible");

        let mut start: Instant;
        let mut total_generation_time: u128 = 0;
        let mut total_filtering_time: u128 = 0;

        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::rngs::OsRng::default();
        for _ in 0..amount_of_tries {
            start = Instant::now();
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            sender.send(KeyPair::from_secret_key(&secp, &secret_key)).unwrap();
            total_generation_time += start.elapsed().as_micros();
        }

        let time_for_generation = total_generation_time / amount_of_tries;
        

        for _ in 0..amount_of_tries {
            start = Instant::now();
            let new_result = receiver.recv();
            match new_result {
                Ok(result) => {
                    let (pubkey_readable, _) = XOnlyPublicKey::from_keypair(&result);
                    if !bech32 {
                        if !filter_pubkeys(&pubkey_readable.to_string(), filter_string.as_str()) {
                            total_filtering_time += start.elapsed().as_micros();
                            continue;
                        }
                    }
                    else {
                        //Convert to bech32
                        let bech_key = to_npub(&pubkey_readable);
                        let new_filter_string = format!("npub1{}", filter_string);
                        if !filter_pubkeys(&bech_key, new_filter_string.as_str()) {
                            total_filtering_time += start.elapsed().as_micros();
                            continue;
                        }
                    }
                    let _tmp_output = format!("{};{}\n", result.display_secret(), pubkey_readable);
                },
                Err(_) => {
                    sleep(Duration::from_secs(1));
                }
            }
            total_filtering_time += start.elapsed().as_micros();
        }

        let time_for_filtering = total_filtering_time / amount_of_tries;

        
        println!("Time for generation: {}µs ({}/{})", time_for_generation, total_generation_time, amount_of_tries);
        println!("\t{} h/s", 1000000 / time_for_generation);
        println!("\t\t{} h/s on 12 cores", (1000000 / time_for_generation) * 12);
        println!("Time for filtering: {}µs ({}/{})", time_for_filtering, total_filtering_time, amount_of_tries);
        return;
}