use log::{debug, info};
use std::fs;
use webpoke::*;

fn main() {
    // initialise logger
    env_logger::init();
    info!("Using sample-config.yaml as workload definition.");
    let cfg_file = fs::read_to_string("sample-config.yaml").expect("Can't read sample-config.json");
    let cfg: PokeConfig = serde_yaml::from_str(&cfg_file).expect("Can't parse YAML");
    debug!("Workload definition: {:?}", cfg);

    // Do requests and deal with stats object.
    let stats = do_requests(&cfg).unwrap();
    for stat in stats.iter() {
        println!("Stats: {}", stat);
    }
}
