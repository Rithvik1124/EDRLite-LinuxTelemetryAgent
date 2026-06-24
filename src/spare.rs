mod detect;
use core::time::Duration;
use std::mem::MaybeUninit;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use structopt::StructOpt;
use trial::*;
use plain::Plain;
use crate::detect::edr_detect_rules;
use libbpf_rs::skel::Skel;
use anyhow::{anyhow, bail, Context, Result};


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
#[derive(Clone, Copy)]


struct ProcEvent{
    event_type: u8,
    pid: u32, //done - 4 bytes]
    uid: u32, // 4 byte
    gid: u32, //4 bytes
    tgid: u32, //done - 4 bytes
    ppid: u32,//done - 4 bytes
    comm: [u8;16],//done - 16 bytes
    exe: String,
    cmdline: String,
    filename: [u8; 512], //done - 512 bytes
    time_stamp:u64,  //done - 8 bytes

}


unsafe impl Plain for ProcEvent {}

impl Default for ProcEvent {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHeader{
    event_type: u8,
}

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
}

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
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(print!("RLIMIT Increased."))
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


fn handle_proc_event( data: &[u8]) {
    let mut event = ProcEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
    println!("Event PID:{}, PPID:{}, UID:{}, GID:{}, TGID:{}, COMM:{:?}, FNAME:{:?}, TSTAMP:{}\n", 
    event.pid,  event.ppid, 
    event.uid,  event.gid,
    event.tgid, convert_result_to_string(&event.comm),
    convert_result_to_string(&event.filename), event.time_stamp,);
}

fn handle_file_event( data: &[u8]) {
    let mut event = FileEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
    let x = convert_result_to_string(&event.filename);
    let mut mode = "";

    match event.operation{
        1=>{
            mode = "Open";
        }
        _=>{
            mode = "idk";
        }
       

    }
    if !(x == ""){
        println!("Event PID:{},\n FNAME:{:?},\n OPERATION: {}\n", 
    event.pid,  x,mode,);

    }
}

fn main() -> Result<()> {
    println!("Proc Event Stuff:\n");
    let opts = Command::from_args();

    let mut skel_builder = TrialSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    let mut rb  = RingBufferBuilder::new();
    rb.add(&skel.maps.rb, |data| {

    let header =
        unsafe { &*(data.as_ptr() as *const EventHeader) };

    match header.event_type {
        0 => handle_proc_event(data),
        1 => handle_file_event(data),
        _ => {}
    }

    0})?;

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