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

