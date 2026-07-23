mod detect;
use core::time::Duration;
use std::collections::HashMap;
use std::fs;
use millisecond::Millisecond;
use millisecond::MillisecondFormatter;
use serde_json::Value;
use serde_json::json;
use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use structopt::StructOpt;
use chrono::{DateTime, Utc};
use trial::*;
use plain::Plain;
use crate::detect::edr_detect_rules;
use libbpf_rs::skel::Skel;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
//might be useful, don't remove
//use std::fs;
//use std::net::Ipv4Addr;
//use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
//use object::Object;
//use object::ObjectSymbol;

mod trial {
    include!("trial.skel.rs");
}

// Timestamp doesnt work


#[repr(C)]
#[derive(Clone, Copy, Debug,)]

pub struct GenEvent {
    pub event_type: u8,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,

    pub tgid: u64,

    pub comm: [u8; 16],
    pub filename: [u8; 512],

    pub dst_ip: u32,
    pub dst_port: u16,

    pub time_stamp: u64,
} 


#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TelemetryEvent {     // this struct can be eliminated by adding a conversion method to GenEvent - no, it can't
    pub event_type: String,         
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u64,

    pub comm: String,
    pub filename: String,

    pub dst_ip: String, //max 15 bytes
    pub dst_port: String, //max 5 bytes

    pub time_stamp: String,
} 


/*
pub struct ProcEvent{
    pub pid: u32,
    pub ppid: u32,
    
    pub TargetFilename: [u8; 512],
}*/


unsafe impl Plain for GenEvent {}

impl Default for GenEvent {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}


// #[repr(C)]
// #[derive(Clone, Copy)]
// struct EventHeader{
//     event_type: u8,
// }

/*
#[repr(C)]

struct FileEvent{
    event_type: u8,
    pid: u32, //done - 4 bytes]
    filename: [u8; 512], //done - 512 bytes
    operation: u8,
}

unsafe impl Plain for FileEvent {}

impl Default for FileEvent {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}*/

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
    
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };

    if ret != 0 {
        bail!("Failed to increase rlimit: {}", std::io::Error::last_os_error());
    }

    Ok(())
}
fn convert_result_to_string(x: &[u8]) -> String {
    let mut output = String::new();

    for i in 0..x.len(){
        if x[i] == 0 {
        break;
    }
        output.push_str(&format!("{}", x[i] as char));

    }


    return output;
}

fn nanosec_to_timestamp(monotonic_ns: u64, offset_ns: i128) -> String {
    let unix_ns = monotonic_ns as i128 + offset_ns;

    let timestamp = DateTime::<Utc>::from_timestamp_nanos(unix_ns as i64);

    timestamp
        .format("%Y-%m-%d %H:%M:%S%.3f UTC")
        .to_string()
}



fn monotonic_to_unix_offset_ns() -> i128 {
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i128;

    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
    }

    let mono_ns =
        ts.tv_sec as i128 * 1_000_000_000 +
        ts.tv_nsec as i128;

    unix_ns - mono_ns
}


/*

fn check_event(event: &GenEvent){
    let cmdline = match fs::read(format!("/proc/{}/cmdline", event.pid)) {
    Ok(v) => v,
    Err(_) => return , };
    
    let x = create_event(event, &mode).unwrap();
    let rule_match = edr_detect_rules::match_rule(&x);
    //if rule_match!=(){   
    println!("Event:{:?} \n Rule:{:?}", &x, &rule_match);}
*/





fn make_event(buff_event: &GenEvent, offset_ns: i128)-> TelemetryEvent{
    let mode :String= match buff_event.event_type {
        10 => "Execve".to_string(),
        11 => "Fork".to_string(),
        12 => "Exit".to_string(),
        13 => "Execveat".to_string(),
        20 => "Unlinkat".to_string(),
        21 => "Renameat".to_string(),
        22=> "Renameat2".to_string(),
        30 => "Connect".to_string(),
        31 => "Accept".to_string(),
        32 => "Bind".to_string(),
        40 => "Mount".to_string(),
        41 => "Unmount".to_string(),
        50 => "Chown".to_string(),
        51 => "Chmod".to_string(),  
        _=> "Unknown".to_string(), 
    };
    let mut event = TelemetryEvent::default();
    let cmdline = match fs::read(format!("/proc/{}/cmdline", buff_event.pid)) {
        Ok(bytes) => convert_result_to_string(&bytes),
        Err(_) => "cmdline expired".to_string(),
    };
        event.event_type = mode;
        event.pid = buff_event.pid;
        event.ppid = buff_event.ppid;
        event.uid = buff_event.uid;
        event.gid = buff_event.gid;
        event.tgid = buff_event.tgid;
        event.dst_ip = buff_event.dst_ip.to_string();
        event.dst_port = buff_event.dst_port.to_string();
        event.comm = cmdline;
        event.pid = buff_event.pid;
        event.filename = convert_result_to_string(&buff_event.filename);
        event.time_stamp = nanosec_to_timestamp(buff_event.time_stamp, offset_ns);
        
    event
    
    
}

// pub struct TelemetryEvent {     // this struct can be eliminated by adding a conversion method to GenEvent
//     pub event_type: String,         // then we can simply call the method instead of having to assign everythin manually in main block
//     pub pid: u32,
//     pub ppid: u32,
//     pub uid: u32,
//     pub gid: u32,
//     pub tgid: u64,

//     pub comm: String,
//     pub filename: String,

//     pub dst_ip: u32,
//     pub dst_port: u16,

//     pub time_stamp: u64,
// } 


#[tokio::main]
async fn main() -> Result<()> {
    // println!("Proc Event Stuff:\n");
    println!("My PID: {}",std::process::id() );
    let opts = Command::from_args();

    let unix_offset_ns = monotonic_to_unix_offset_ns();

    let client = Client::new();

    let (tx, mut rx) = mpsc::channel::<TelemetryEvent>(1024); // 1024 is the channel capacity, both want EVent here

    let http_client = client.clone();
    tokio::spawn(async move {
        while let Some(some_event) = rx.recv().await {
            if let Err(e) = http_client
                .post("http://127.0.0.1:3000/publish")
                .json(&some_event)
                .send()
                .await
            {
                eprintln!("Failed to send telemetry: {}", e);
            }
        }
    });

    let mut skel_builder = TrialSkelBuilder::default();

    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Sending userspace - ./target/debug/edr-agent PID to kernspace 'agent_tgid'
    let mut skel = open_skel.load()?;
    let key: u32 = 0;
    let value: u32 = std::process::id();

    skel.maps
    .agent_pid_map
    .update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::ANY)?;
    skel.attach()?;
    let mut rb  = RingBufferBuilder::new();
        

    let tx = tx.clone();
    rb.add(&skel.maps.rb, move |data| {
    let mut event = GenEvent::default();
   
    if plain::copy_from_bytes(&mut event, data).is_err() {

        return 0;
    }

    let telemetry = make_event(&event, unix_offset_ns);

    if let Err(e) = tx.try_send(telemetry) {
        eprintln!("Telemetry queue full, dropping event: {}", e);
    }

    0
})?;
    let rb = rb.build()?;
    

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(100))?;
    }


    Ok(())
}