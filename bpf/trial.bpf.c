#include "../vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Define tracepoint, triggered when a process executes the unlinkat system call (deletes a file)

#define TASK_COMM_LEN 16
#define FILENAME_LEN 512
//#define CMDLINE 256
#define ARGV_LEN 4096

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10


struct gen_event {
    __u8 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;

    __u64 tgid;

    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];

    __u32 dst_ip;
    __u16 dst_port;

    __u64 time_stamp;
};

// Define ring buffer map sudo bpftrace -lv tracepoint:syscalls:sys_enter_execve

/*
struct process_event {
    __u8 event_type;
    __u32 pid; //done - 4 bytes]
    __u32 uid; // 4 byte
    __u32 gid; //4 bytes
    __u32 tgid; //done - 4 bytes
    __u32 ppid; //done - 4 bytes
    char comm[TASK_COMM_LEN]; //done - 16 bytes
    char cmdline[FILENAME_LEN];
    char filename[FILENAME_LEN]; //done - 512 bytes
    __u64 time_stamp; //done - 8 bytes

}; */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");



SEC("tracepoint/syscalls/sys_enter_execve")

int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
    {
    struct gen_event *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->event_type = 0; //execve event = 0
    // 1. Get process PID
    __u64 tpid = bpf_get_current_pid_tgid();
    event->pid = tpid;
    event->tgid = tpid >> 32;    
    // 2. Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    const char *filename =
        (const char *)ctx->args[0];

    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename
    );
    //u32 filelen = sizeof(filename);
    __u64 ugid = bpf_get_current_uid_gid();
    event-> uid = ugid ;
    event-> gid = ugid >> 32;
    event-> time_stamp = bpf_ktime_get_ns();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    //bpf_printk("timestamp: %llu pid: %d, comm: %s, filename: %s, tgid: %d ppid: %d\n", time_stamp, pid, comm, tgid, ppid);
    bpf_ringbuf_submit(event, 0);

    return 0;
}



//filesystem -orw sudo bpftrace -lv tracepoint:syscalls:sys_enter_openat
/*
struct file_event {
    __u8 event_type;
    __u32 pid; //done - 4 bytes]
    char filename[FILENAME_LEN]; //done - 512 bytes
    __u8 mode;
};
*/

SEC("tracepoint/syscalls/sys_enter_openat")

int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
    {
    struct gen_event *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->event_type = 1; //openat event = 1

    // 1. Get process PID
    __u32 pid = bpf_get_current_pid_tgid();
    event->pid = pid; 
    const char *filename = (const char *)ctx->args[1];

    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename
    );
    // 2. Get process name
    //const char *filename =         (const char *)ctx->args[1];
    //u32 filelen = sizeof(filename);
    //__u64 ugid = bpf_get_current_uid_gid();
    //event-> time_stamp = bpf_ktime_get_ns();
    //struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    //bpf_printk("timestamp: %llu pid: %d, comm: %s, filename: %s, tgid: %d ppid: %d\n", time_stamp, pid, comm, tgid, ppid);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/*
struct network_event {
    __u8 event_type;
    __u32 pid; //done - 4 bytes]
    char filename[16]; //done - 512 bytes
};*/
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct gen_event *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2; //connect event = 2
    event->pid = bpf_get_current_pid_tgid();

    struct sockaddr addr;
    const char *addr_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
    if (addr.sa_family == AF_INET) {
        struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;

        event->dst_port = BPF_CORE_READ(in4, sin_port);
        event->dst_ip   = BPF_CORE_READ(in4, sin_addr.s_addr);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}