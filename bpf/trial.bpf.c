#include "../vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Define tracepoint, triggered when a process executes the unlinkat system call (deletes a file)

#define TASK_COMM_LEN 16
#define FILENAME_LEN 512
#define ARGV_LEN 4096


// Define ring buffer map
struct event_t {
    __u32 pid; //done - 4 bytes]
    __u32 uid; // 4 byte
    __u32 gid; //4 bytes
    __u32 tgid; //done - 4 bytes
    __u32 ppid; //done - 4 bytes
    char comm[TASK_COMM_LEN]; //done - 16 bytes
    char filename[FILENAME_LEN]; //done - 512 bytes
    __u64 time_stamp; //done - 8 bytes

};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")

int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
    {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

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

