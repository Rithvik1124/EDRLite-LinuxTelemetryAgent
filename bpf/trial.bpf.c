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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} agent_pid_map SEC(".maps");


//created general event class bcoz too many class

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



/*
⠀Modes 🤖🤖🤖🤖

-- Processes: 1x --
tracepoint:syscalls:sys_enter_execve = 10
tracepoint:sched:sched_process_exec = 11
tracepoint:sched:sched_process_fork = 12
tracepoint:sched:sched_process_exit = 13

-- Files: 2x --
tracepoint:syscalls:sys_enter_openat = 20
tracepoint:syscalls:sys_enter_unlinkat = 21
tracepoint:syscalls:sys_enter_renameat = 22
tracepoint:syscalls:sys_enter_renameat2 = 23

-- Network: 3x --

tracepoint:syscalls:sys_enter_connect = 30
tracepoint:syscalls:sys_enter_accept = 31
tracepoint:syscalls:sys_enter_bind: 32

-- Socket messages: 4x --
tracepoint:syscalls:sys_enter_sendmsg: 40
tracepoint:syscalls:sys_enter_sendmmsg: 41
tracepoint:syscalls:sys_enter_sendto: 42

-- Filesystem: 5x --

tracepoint:syscalls:sys_enter_mount: 50
tracepoint:syscalls:sys_enter_umount: 51

Permissions: 6x
tracepoint:syscalls:sys_enter_chown: 60
tracepoint:syscalls:sys_enter_chmod: 61

*/



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




// SYSCALLS!!! ◝(ᵔᗜᵔ)◜

//10

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    

    __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 10;
    event->pid = pid;
    event->tgid = pid_tgid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename);

    __u64 ugid = bpf_get_current_uid_gid();
    event->uid = (__u32)ugid;
    event->gid = (__u32)(ugid >> 32);

    event->time_stamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//11
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    

    __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 11;
    event->pid = pid;
    event->tgid = pid_tgid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    __u32 loc = ctx->__data_loc_filename;

    const char *filename = (const char *)ctx + (loc & 0xFFFF);

    bpf_probe_read_kernel_str(event->filename,
                              sizeof(event->filename),
                              filename);

    __u64 ugid = bpf_get_current_uid_gid();
    event->uid = (__u32)ugid;
    event->gid = (__u32)(ugid >> 32);

    event->time_stamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//12


SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    

    __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 12;
    event->pid = pid;
    event->tgid = pid_tgid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    __u64 ugid = bpf_get_current_uid_gid();
    event->uid = (__u32)ugid;
    event->gid = (__u32)(ugid >> 32);

    event->time_stamp = bpf_ktime_get_ns();

    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = ctx->parent_pid;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//13


SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    

    __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 13;
    event->pid = pid;
    event->tgid = pid_tgid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    __u64 ugid = bpf_get_current_uid_gid();
    event->uid = (__u32)ugid;
    event->gid = (__u32)(ugid >> 32);

    event->time_stamp = bpf_ktime_get_ns();

    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

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


//FileSystems 2x

//20 tracepoint:syscalls:sys_enter_openat

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 20;
    event->pid = pid;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
struct network_event {
    __u8 event_type;
    __u32 pid; //done - 4 bytes]
    char filename[16]; //done - 512 bytes
};*/

//21 tracepoint:syscalls:sys_enter_unlinkat


SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 21;
    event->pid = pid;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//22 tracepoint:syscalls:sys_enter_renameat


SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 22;
    event->pid = pid;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 23 tracepoint:syscalls:sys_enter_renameat2


SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 23;
    event->pid = pid;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(
        event->filename,
        sizeof(event->filename),
        filename);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}


//30 tracepoint:syscalls:sys_enter_connect

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//31 tracepoint:syscalls:sys_enter_accept
SEC("tracepoint/syscalls/sys_enter_accept")

int trace_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

//32 tracepoint:syscalls:sys_enter_bind:
int trace_enter_bind(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}


//40 tracepoint:syscalls:sys_enter_sendmsg
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}


//41 tracepoint:syscalls:sys_enter_sendmmsg
SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}



//42 tracepoint:syscalls:sys_enter_sendto
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// tracepoint:syscalls:sys_enter_mount: 50
SEC("tracepoint/syscalls/sys_enter_mount")
int trace_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int trace_enter_umount(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
     __u32 key = 0;
    __u32 *agent = bpf_map_lookup_elem(&agent_pid_map, &key);

    if (agent && *agent == tgid)
        return 0;

    struct gen_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->event_type = 2;
    event->pid = pid;

    struct sockaddr_in addr4 = {};

    if (bpf_probe_read_user(&addr4, sizeof(addr4),
                            (const void *)ctx->args[1]) == 0) {

        if (addr4.sin_family == AF_INET) {
            event->dst_port = __builtin_bswap16(addr4.sin_port);
            event->dst_ip = addr4.sin_addr.s_addr;
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}


// tracepoint:syscalls:sys_enter_umount: 51