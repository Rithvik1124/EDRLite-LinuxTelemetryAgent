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
 -- maybe find a way to make backup flakes or snapshots if it is plausible(x3)

hope to god I don't crash out


