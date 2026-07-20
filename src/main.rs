mod detect;
use core::time::Duration;
use std::fs;
use millisecond::Millisecond;
use millisecond::MillisecondFormatter;
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

use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};

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
#[derive(Clone, Copy, Debug)]

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



fn handle_proc_event( event: &GenEvent) {
    //plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
    let cmdline = match fs::read(format!("/proc/{}/cmdline", event.pid)) {
    Ok(v) => v,
    Err(_) => return , };
    let mode = match event.event_type {
        0 => "Execve",
        1 => "Openat",
        2 => "Connect",
        _ => "Unknown",
    };
    if (convert_result_to_string(&cmdline)!="./target/debug/edr-agent"){
         println!(" Event Mode:{}, PID:{}, PPID:{}, UID:{}, GID:{}, TGID:{}, COMM:{:?}, FNAME:{:?}, TSTAMP:{:?}\n",  mode,
    event.pid,  event.ppid, 
    event.uid,  event.gid,
    event.tgid, convert_result_to_string(&event.comm), convert_result_to_string(&event.filename), nanosec_to_24_hr(event.time_stamp),);
    println!("cmdline:: {:?}",convert_result_to_string(&cmdline));

    }
   
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


fn create_event(buff_event: &GenEvent, mode: &str) -> anyhow::Result<Event>{
    //creates event rather than doing json-str-event stuff done in edr_detect_rules.rs
    let mut event = Event::new();
    let cmdline = match fs::read(format!("/proc/{}/cmdline", buff_event.pid)) {
        Ok(bytes) => convert_result_to_string(&bytes),
        Err(_) => "cmdline expired".to_string(),
    };
        event.insert("Mode", mode);
        event.insert("PID", buff_event.pid);
        event.insert("PPID", buff_event.ppid);
        event.insert("UID", buff_event.uid);
        event.insert("GID", buff_event.gid);
        event.insert("TGID", buff_event.tgid);
        event.insert("Image", convert_result_to_string(&buff_event.filename));
        event.insert("TimeStamp", nanosec_to_24_hr(buff_event.time_stamp));
        event.insert("CommandLine", cmdline);
    
    
     return Ok(event);

    }


fn check_event(event: &GenEvent){
    let cmdline = match fs::read(format!("/proc/{}/cmdline", event.pid)) {
    Ok(v) => v,
    Err(_) => return , };
    let mode = match event.event_type {
        10 => "Execve",
        11 => "Fork",
        12 => "Exit",
        13 => "Execveat",
        20 => "Unlinkat",
        21 => "Renameat",
        22=> "Renameat2",
        30 => "Connect",
        31 => "Accept",
        32 => "Bind",
        40 => "Mount",
        41 => "Unmount",
        50 => "Chown",
        51 => "Chmod",  
        _=> "Unknown", 
    };
    let x = create_event(event, mode).unwrap();
    let rule_match = edr_detect_rules::match_rule(&x);
    if rule_match!=(){
        println!("Event:{:?} \n Rule:{:?}", &x, &rule_match);
    }
    
}


fn main() -> Result<()> {
    println!("Proc Event Stuff:\n");
    println!("My PID: {}",std::process::id() );
    let opts = Command::from_args();

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

    //Sends our edr-agent thread group id to the kernel agent_tgid map - kernel does the rest of the blocking, we've saved between 60-80% of cpu usage from this - else it was arounf 103 TwT

    skel.maps
    .agent_pid_map
    .update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::ANY)?;
    skel.attach()?;
    let mut rb  = RingBufferBuilder::new();
    rb.add(&skel.maps.rb, |data| {
    let mut event = GenEvent::default();

    if plain::copy_from_bytes(&mut event, data).is_err() {
        return 0;
    }
    /*
    println!(
        "[RAW] type={} pid={} filename={}",
        event.event_type,
        event.pid,
        convert_result_to_string(&event.filename)
    );*/

    //handle_event_type(&event);

    check_event(&event);

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

