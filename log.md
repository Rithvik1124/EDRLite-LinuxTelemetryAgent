## Log of Issues
**This is a log of the issues I am and will be coming across due to my lack of thinking ahead, so that I keep track of what's done and preserve my sanity.**

### 13/07/2026

**Today's issue:** ./target/debug/edr-agent reports its own openat triggers
**What I tried:**
1) Tried to access the pid of agent through kernel space in trial,bpf.c - didn't work (self explanatory, not to me)
2) Tried to make a map in kernelspace, but couldnt figure out how to send the userspace pid to kernel with maps - lack of documentations(and skill issue)

**What worked for me:**
1) Used maps, before I didn't check properly and tried to use UserRingBuffer for a solution to share data between kernel and userspace, wouldn't work.
2) Created an agent_tgid map with key 0 and value as the tgid
3) Thought that tgid and pid could be used the same way - apparently not, tgid is actually what I thought PID was, and PID is actually the thread id;
**tl;dr: TGID is the process identifier; PID is the thread identifier.**
4) Sending the tgid through MapCore's update()

**Overall headache rating: 7/10 - would go through it again.**

**Conclusion:** Giving a brief read to the documentation would've been helpful, and libbpf-c would be a better choice if I wasn't so adamant on trying the "next best language"

### 15/07/2026
1) Removed sockets triggers due to waaaaaaayyyyy too much telemetry
2) Added and removed a few telemetries
3) Used argv for execve and execveat for reduced load
4) will cache the argv instead of doing a majority proc read each time for every event type

**Confusion very much**

### 17/07/2026
Panics for some reason, IDK why, gets an error in unwrap then returns an error:

thread 'main' (72689) panicked at src/main.rs:228:39:
called `Result::unwrap()` on an `Err` value: failed to read /proc/<pid>/cmdline

Caused by:
    No such file or directory (os error 2)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

thread 'main' (72689) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panicking.rs:225:5:
panic in a function that cannot unwind
stack backtrace:
   0:     0x560c53cd452a - std[52919eca6bce4da3]::backtrace_rs::backtrace::libunwind::trace
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/../../backtrace/src/backtrace/libunwind.rs:117:9
   1:     0x560c53cd452a - std[52919eca6bce4da3]::backtrace_rs::backtrace::trace_unsynchronized::<std[52919eca6bce4da3]::sys::backtrace::_print_fmt::{closure#1}>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/../../backtrace/src/backtrace/mod.rs:66:14
   2:     0x560c53cd452a - std[52919eca6bce4da3]::sys::backtrace::_print_fmt
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/sys/backtrace.rs:74:9
   3:     0x560c53cd452a - <<std[52919eca6bce4da3]::sys::backtrace::BacktraceLock>::print::DisplayBacktrace as core[18c8dd30382e7099]::fmt::Display>::fmt
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/sys/backtrace.rs:44:26
   4:     0x560c53cebd9a - <core[18c8dd30382e7099]::fmt::rt::Argument>::fmt
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/fmt/rt.rs:152:76
   5:     0x560c53cebd9a - core[18c8dd30382e7099]::fmt::write
   6:     0x560c53cd96f2 - std[52919eca6bce4da3]::io::default_write_fmt::<std[52919eca6bce4da3]::sys::stdio::unix::Stderr>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/io/mod.rs:621:11
   7:     0x560c53cd96f2 - <std[52919eca6bce4da3]::sys::stdio::unix::Stderr as std[52919eca6bce4da3]::io::Write>::write_fmt
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/io/mod.rs:1976:13
   8:     0x560c53cbd0bf - <std[52919eca6bce4da3]::sys::backtrace::BacktraceLock>::print
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/sys/backtrace.rs:47:9
   9:     0x560c53cbd0bf - std[52919eca6bce4da3]::panicking::default_hook::{closure#0}
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:292:27
  10:     0x560c53ccee51 - std[52919eca6bce4da3]::panicking::default_hook
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:319:9
  11:     0x560c53ccf00b - std[52919eca6bce4da3]::panicking::panic_with_hook
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:825:13
  12:     0x560c53cbd1aa - std[52919eca6bce4da3]::panicking::panic_handler::{closure#0}
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:691:13
  13:     0x560c53cb1ce9 - std[52919eca6bce4da3]::sys::backtrace::__rust_end_short_backtrace::<std[52919eca6bce4da3]::panicking::panic_handler::{closure#0}, !>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/sys/backtrace.rs:182:18
  14:     0x560c53cbdc4d - __rustc[8068f81614cfe5c]::rust_begin_unwind
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:689:5
  15:     0x560c53cec3fd - core[18c8dd30382e7099]::panicking::panic_nounwind_fmt::runtime
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panicking.rs:122:22
  16:     0x560c53cec3fd - core[18c8dd30382e7099]::panicking::panic_nounwind_fmt
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/intrinsics/mod.rs:2448:9
  17:     0x560c53cec37b - core[18c8dd30382e7099]::panicking::panic_nounwind
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panicking.rs:225:5
  18:     0x560c53cec507 - core[18c8dd30382e7099]::panicking::panic_cannot_unwind
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panicking.rs:337:5
  19:     0x560c539091fe - libbpf_rs::ringbuf::RingBufferBuilder::call_sample_cb::h0c07f3208e5b8e08
                               at /home/ritwix/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libbpf-rs-0.25.0/src/ringbuf.rs:146:5
  20:     0x560c539394d1 - ringbuf_process_ring
                               at /home/ritwix/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libbpf-sys-1.5.1+v1.5.1/libbpf/src/ringbuf.c:260:11
  21:     0x560c539395dc - ring_buffer__poll
                               at /home/ritwix/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libbpf-sys-1.5.1+v1.5.1/libbpf/src/ringbuf.c:349:9
  22:     0x560c5390914d - libbpf_rs::ringbuf::RingBuffer::poll_raw::h8424756e14f6471b
                               at /home/ritwix/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libbpf-rs-0.25.0/src/ringbuf.rs:180:18
  23:     0x560c539090e8 - libbpf_rs::ringbuf::RingBuffer::poll::h06ace7c93273352b
                               at /home/ritwix/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libbpf-rs-0.25.0/src/ringbuf.rs:188:24
  24:     0x560c53802d58 - edr_agent::main::h01d65b8f1f5b0c10
                               at /data/CodingStuff/VMStuff/EDRLite/spare_agent/src/main.rs:294:12
  25:     0x560c5380becb - core::ops::function::FnOnce::call_once::h51d97508184beee0
                               at /home/ritwix/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  26:     0x560c5380683d - std::sys::backtrace::__rust_begin_short_backtrace::h2661e8b4a028ef2d
                               at /home/ritwix/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/backtrace.rs:166:18
  27:     0x560c538005c1 - std::rt::lang_start::{{closure}}::hcf0e605faaabbe5d
                               at /home/ritwix/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/rt.rs:206:18
  28:     0x560c53cce114 - <&dyn core[18c8dd30382e7099]::ops::function::Fn<(), Output = i32> + core[18c8dd30382e7099]::marker::Sync + core[18c8dd30382e7099]::panic::unwind_safe::RefUnwindSafe as core[18c8dd30382e7099]::ops::function::FnOnce<()>>::call_once
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/ops/function.rs:287:21
  29:     0x560c53cce114 - std[52919eca6bce4da3]::panicking::catch_unwind::do_call::<&dyn core[18c8dd30382e7099]::ops::function::Fn<(), Output = i32> + core[18c8dd30382e7099]::marker::Sync + core[18c8dd30382e7099]::panic::unwind_safe::RefUnwindSafe, i32>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:581:40
  30:     0x560c53cce114 - std[52919eca6bce4da3]::panicking::catch_unwind::<i32, &dyn core[18c8dd30382e7099]::ops::function::Fn<(), Output = i32> + core[18c8dd30382e7099]::marker::Sync + core[18c8dd30382e7099]::panic::unwind_safe::RefUnwindSafe>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:544:19
  31:     0x560c53cce114 - std[52919eca6bce4da3]::panic::catch_unwind::<&dyn core[18c8dd30382e7099]::ops::function::Fn<(), Output = i32> + core[18c8dd30382e7099]::marker::Sync + core[18c8dd30382e7099]::panic::unwind_safe::RefUnwindSafe, i32>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panic.rs:359:14
  32:     0x560c53cce114 - std[52919eca6bce4da3]::rt::lang_start_internal::{closure#0}
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/rt.rs:175:24
  33:     0x560c53cce114 - std[52919eca6bce4da3]::panicking::catch_unwind::do_call::<std[52919eca6bce4da3]::rt::lang_start_internal::{closure#0}, isize>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:581:40
  34:     0x560c53cce114 - std[52919eca6bce4da3]::panicking::catch_unwind::<isize, std[52919eca6bce4da3]::rt::lang_start_internal::{closure#0}>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:544:19
  35:     0x560c53cce114 - std[52919eca6bce4da3]::panic::catch_unwind::<std[52919eca6bce4da3]::rt::lang_start_internal::{closure#0}, isize>
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panic.rs:359:14
  36:     0x560c53cce114 - std[52919eca6bce4da3]::rt::lang_start_internal
                               at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/rt.rs:171:5
  37:     0x560c538005a7 - std::rt::lang_start::h8aacbef210635233
                               at /home/ritwix/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/rt.rs:205:5
  38:     0x560c53802f5e - main
  39:     0x7fe0e78e55b5 - __libc_start_call_main
  40:     0x7fe0e78e5668 - __libc_start_main_alias_1
  41:     0x560c537fee65 - _start
  42:                0x0 - <unknown>
thread caused non-unwinding panic. aborting.
Aborted                    sudo -E ./target/debug/edr-agent
### 17/07/2026
Okay so a major improvement from last time somehow we've gone from 104% cpu usage to ~1.5% usage, idk if I trust it, everything works as it's supposed to but how?
anyways, all I need to do now is get back to the caching and stuff for proc tree and more optimization(idk if its even worth the time tbh or the reward)

What else? other than the responding part I need to get done with yara and ioc for network and file stuff, get a bit more widespread sigma rules, and yeah

My plan:

if we identify something malicious, we first:
log everything being done below:
 -- isolate automatically through systemd-run and make every bin stuff into read only(idk how plausible ts is but let's see)
 -- cut off network in case of a suspected breach then kill any and every process related to the breach
 -- just send every log and stuff to the server and maybe if plausible(idk what plausible means) create a vm link to the server for better recovering and response

New IDEA we will be sticking with:
1) A "snitching council" which will allow us to make it so that we have multiple endpoints which will be monitoring each other at the same point for low risk problems
   like opening unwanted or unknown links, downloading from suspicious links etc, which allows for the server to manage more better events rather than focusing on an employee's misdoings
2) Each endpoint will be given 'n' endpoints to snitch on, if a problem is found it will reach a consensus with other endpoints, it'll reach a consensus and make 
   the correspongding actions
3) The given flag will be sent to the server to review
4) This allows for the server load to be reduced

It's like an i2p system but for snitching, which makes the loads on the server easier, of course it must be checked for false positives, and well, low level 
compromises lead to a lot of events daily, which is a mental and compute overload on both the server and the person sitting behind the server. Hence, given each endpoint snitches on ~3-4 endpoints, we can distribute the compute of the server from running 70% for all endpoints to just running endpoints to maybe half(We wont find out without trying this first). So, a cleaner server environment, less headaches and stuff.

It might not be as effective, maybe, but we wont know unless we do it, plus its a conversation starter in interviews(which is something I want
(call it attention seeking idc)).


Need to check again:
How to make this stronger

There are a few ways to reduce that risk:

Server-assigned peers. Endpoints don't choose who monitors whom, and assignments rotate periodically.
Random audits. The server occasionally asks an endpoint for its integrity report directly instead of relying on peers.
Independent local detection. Each endpoint still sends high-severity events (e.g., code injection, driver loading, agent tampering) directly to the server without waiting for consensus.
Signed integrity reports. Peers verify signatures and timestamps, making replay attacks harder.
Majority for low-risk events only. Use peer consensus to suppress noisy events like suspicious downloads or unknown URLs, but never for critical detections.

so I'll have to create protocols, basically set roles, and divide workload equally among peers, each role would be something from checking hashes to yara to sigma, and based on their reached consensus, we'd have to dynamically use that protocol with every check, if - a endpoint gets compromised, or an endpoint isn't on the network yet, so the roles will change and the framework will change dynamically

my current telemetry agent roughly uses 2% cpu at max, I'll have to check with the detection parts, but given that an endpoint supposedly takes 2 roles, 
sigma yara, yara ioc, or sigma ioc, that isn't any more than 4-5% compute, the response will obviously be taken by the server, as you can't rely on c
omputers alone, every consensus along with the proc tree and enrichment rather, will be sent to the server rather than sending several events at a time for
the server to decide


yara checks will be done locally so we'll have 3 roles instead, so that'll be sigma, ioc and consensus(basically scoring and sending the event report to the server for responding), after that, the assigment have to decided on 3 things:
1) current workload on the endpoints within our network
2) roles that are required(stuff like sigma or consensus has less compute(i think), so maybe that can change the scoring)
3) which endpoints the current endpoint has to review

something has to be done dynamically and asynchronously without stopping the peers to maintain continuity

but what role do you assign, that needs to be checked too, I need to check how much capacity each role has currently, if have 90% of ioc full with moer endpoints being ioc checks, while other 2 are barely half full due to their compute value, I'll have to decide on which role to give the new endpoint or an endpoint which doesn't have much compute load

Instead of asking peers to classify an event as "benign" or "malicious," have them contribute context:

"I've seen this process hash 500 times."
"This registry modification is common on my machine."
"I've never observed this DLL."
"This parent-child process relationship is rare."

The originating endpoint then combines:

its own detection rules,
peer observations,
and server intelligence,

to make a more informed decision.

That avoids relying on peers to make security decisions while still reducing redundant uploads.

Overall, this is a plausible research direction. It overlaps with ideas from collaborative intrusion detection, federated learning, and edge analytics. The difficult parts are designing a consensus mechanism that resists compromised peers, limits Bluetooth overhead, and ensures that truly critical detections are never delayed.

the protocol:

Peer assignment.
Event generation.
Consensus request/response.
Upload decision.
Peer reassignment.
Failure handling.