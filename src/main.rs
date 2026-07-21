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
use std::string;
use trial::*;
use plain::Plain;
use crate::detect::edr_detect_rules;
use libbpf_rs::skel::Skel;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
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
pub struct TelemetryEvent {     // this struct can be eliminated by adding a conversion method to GenEvent
    pub event_type: u8,         // then we can simply call the method instead of having to assign everythin manually in main block
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u64,

    pub comm: String,
    pub filename: String,

    pub dst_ip: u32,
    pub dst_port: u16,

    pub time_stamp: u64,
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


#[repr(C)]
#[derive(Clone, Copy)]
struct EventHeader{
    event_type: u8,
}

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

fn nanosec_to_24_hr(nanosec: u64) -> std::string::String{
    let computed_millis = nanosec/1000000;
    let ms = Millisecond::from_nanos(computed_millis);
    return ms.pretty();

    
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





fn make_event(buff_event: &GenEvent)-> HashMap<String, String>{
    let cmdline = match fs::read(format!("/proc/{}/cmdline", buff_event.pid)) {
    Ok(v) => convert_result_to_string(&v),
    Err(_) =>"cmdline expired".to_string(), };
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
    let mut event = HashMap::<String, String>::new();
    let cmdline = match fs::read(format!("/proc/{}/cmdline", buff_event.pid)) {
        Ok(bytes) => convert_result_to_string(&bytes),
        Err(_) => "cmdline expired".to_string(),
    };
        event.insert("Mode".to_string(), mode);
        event.insert("PID".to_string(), buff_event.pid.to_string());
        event.insert("PPID".to_string(), buff_event.ppid.to_string());
        event.insert("UID".to_string(), buff_event.uid.to_string());
        event.insert("GID".to_string(), buff_event.gid.to_string());
        event.insert("TGID".to_string(), buff_event.tgid.to_string());
        event.insert("Image".to_string(), convert_result_to_string(&buff_event.filename));
        event.insert("TimeStamp".to_string(), nanosec_to_24_hr(buff_event.time_stamp));
        event.insert("CommandLine".to_string(), cmdline);
    event
    
    
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Proc Event Stuff:\n");
    println!("My PID: {}",std::process::id() );
    let opts = Command::from_args();
    let client = Client::new();

    let (tx, mut rx) = mpsc::channel::<serde_json::Value>(1024); // 1024 is the channel capacity, both want EVent here

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

    let telemetry = serde_json::to_value(make_event(&event)).unwrap();

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

