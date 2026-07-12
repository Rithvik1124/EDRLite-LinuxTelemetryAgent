## Log of Issues
**This is a log of the issues I am and will be coming across due to my lack of thinking ahead, so that I keep track of what's done.**

### 13/07/2026

**Today's issue:** ./target/debug/edr-agent reports its own openat triggers
**What I tried:**
1) Tried to access the pid of agent through kernel space in trial,bpf.c - didn't work (self explanatory, not to me)
2) Tried to make a map in kernelspace, but couldnt figure out how to send the userspace pid to kernel with maps - lack of documentations(and skill issue)

**What worked for me:**
-- Still working on it
