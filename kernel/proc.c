#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "pstat.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

const int MAX_TICKS_PER_QUEUE[4] = {4, 8, 16, 32}; // Define max_ticks_per_queue

// struct spinlock mlfq_tickslock; // required for multi core implentation
int mlfq_ticks = 0;
int newticks = 0;  //rempve (for debug purposes)
const int MLFQ_PB_VOO_DOO_CONST = 200;
int current_priority_queue = 0;

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

void
procinfo_helper(struct pstat * ps3) {
  struct proc * p;
  printf("\n in proc info helper %s %d \n",myproc()->name, myproc()->state);
  for (int i = 0; i < NPROC; i++) {
        ps3->inuse[i] = 0;
        ps3->pid[i] = 0;
        ps3->priority[i] = 0;
        for (int j = 0; j < 4; j++) {
            ps3->ticks[i][j] = 0;
        }
  }

  int i = 0;
  for(p = proc; p < &proc[NPROC]; p++) {
    if(p->state != UNUSED) {
      ps3->inuse[i] = 1;
    }
    ps3->pid[i] = p->pid;
    ps3->priority[i] = p->curq;
    for (int j = 0; j < 4; j++) {
        ps3->ticks[i][j] = p->queue_ticks[j];
    }
    i+=1;
  }
}

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->state = UNUSED;
      p->kstack = KSTACK((int) (p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc*
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int
allocpid()
{
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  //printf("ALLOCPROC ENTERED \n");
  p->pid = allocpid();
  p->state = USED;

  //Added for MLFQ
  p->curq = 0;  //putting the newly allocated process in the topmost queue
  p->curq_ticks_left = MAX_TICKS_PER_QUEUE[p->curq];  //initializing the time slice of the process with 4 ticks
  p->curq_run = 0;  //process hasn't been scheduled yet
  for (int i = 0; i < 4; i++) {
        p->queue_ticks[i] = 0; //initializing time spent by process in each queue to 0
  }
  current_priority_queue = 0; //since the process was allocated in the topmost priority queue, our scheduler thread will now schedule from topmost queue
  
  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;
  // printf("process name: %s", p->name);
  // printf("ALLOCPROC exit \n");
  // printf("\n\n\n");
  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
  
  //Added for MLFQ
  p->curq = -1; 
  p->curq_ticks_left = 0;
  p->curq_run = 0;
  for (int i = 0; i < 4; i++) {
        p->queue_ticks[i] = 0; //resetting time spent by process in each queue to 0
  }
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
  0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
  0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
  0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
  0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
  0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc(); //adds the new process in the topmost priority queue, we dont need to do anything here
  initproc = p;
  
  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){ //adds the new process in the topmost priority queue, we dont need to do anything here
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
exit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);
  
  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if(pp->state == ZOMBIE){
          // Found one.
          pid = pp->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                  sizeof(pp->xstate)) < 0) {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

void prioriy_boost() { //not holding a lock on this function call
  mlfq_ticks = 0; //setting the ticks back to 0
  struct proc *p;

  //reassigning the queue and time slices for each process. Also setting the current run to 0
  for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      p->curq_run = 0;
      p->curq = 0;
      p->curq_ticks_left = MAX_TICKS_PER_QUEUE[0];
      release(&p->lock);
  }
  current_priority_queue = 0;  //setting the queue back to topmost queue
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  
  c->proc = 0;
  for(;;){
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
    int process_found = 0; //to check if a process was found in the current priority queue. Initially set to 0. If found then 1.

    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if((p->state == RUNNABLE)&& (p->curq == current_priority_queue)) { // 
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        process_found = 1;
        printf("p->curq: %d \n", p->curq);
        printf("current queue global var: %d \n", current_priority_queue);
        printf("current run: %d \n", p->curq_run);
        printf("current ticks left: %d \n", p->curq_ticks_left);
        printf("name: %s \n", p->name);
        printf("ticks: %d, newticks: %d", ticks, newticks);
        printf("\n\n\n");
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->context, &p->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
      release(&p->lock);
      
      if (mlfq_ticks == MLFQ_PB_VOO_DOO_CONST) {
        prioriy_boost();
        printf("\n------------------------Priority Boost-------------------------\n");
        break; //start from the top in the queue . We do so because when processes are allocated we choose the ones with lowest index.
      }
    }
    if (process_found == 0) { //if no process was found in the current priority queue, we move to the next priority queue
      if (current_priority_queue != 3) { //not the bottommost priority queue
        current_priority_queue += 1;
      }
      else { //when no process was found but we are in the last priority queue, we check what is the lowest queue with a process and shift there
        // current_priority_queue is 3 before this loop
        for(p = proc; p < &proc[NPROC]; p++) {
          acquire(&p->lock);
          if((p->state == RUNNABLE) && (p->curq < current_priority_queue)) {
            current_priority_queue = p->curq;   //updating the current priority queue to whichever process is in the priority queue with highest priority
          }
          release(&p->lock);
        }
      }
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

int
mlfq_yield_helper(struct proc *p) {  //When called from yield, 1 returned when there should be a context switch, 0 returned when current process is allowed to continue.
  p->curq_ticks_left -= 1;
  p->curq_run += 1;
  p->queue_ticks[p->curq] += 1; //incrementing the time spent by process in current priority queue by 1
  // printf("\n %s entered yield \n", p->name);
  // printf("Inside mlfq yield helper");
  printf("\n current run: %d \n", p->curq_run);
  // printf("current ticks left: %d \n", p->curq_ticks_left);
  // printf("End of mlfq yield helper");
  // acquire(&mlfq_ticks);  //required for multicore
  mlfq_ticks += 1;
  newticks += 1; //rempve (for debug purposes)
  if (mlfq_ticks == MLFQ_PB_VOO_DOO_CONST) {
    //release(&mlfq_ticks); 
    return 1; //this will ensure the context switch from cur proc kernel thread to scheduler thread, and then in the scheduler thread there will be a priority boost
  }   //below code doesn't need to be executed because there will be a prioriy boost in kernel thread so it wont matter
  //release(&mlfq_ticks);     //required for multicore

  if(p->curq_ticks_left == 0) {  //if time slice of current process is over
    if (p->curq != 3) { //if curq is not 3, that is not the last priority queue
      p->curq += 1;
      p->curq_ticks_left = MAX_TICKS_PER_QUEUE[p->curq]; //set the time slice of the process to max ticks depending on the queue
      p->curq_run = 0;
      return 1;
    }
    else {
      if (p->curq_run != MAX_TICKS_PER_QUEUE[3]) { //if in current scheduling process has not ran for 32 ticks
        p->curq_ticks_left = MAX_TICKS_PER_QUEUE[3] - p->curq_run; //set the time slice again to 32 - whatever time it has been running for so far. 
        //We do so to ensure that no process runs for more than 32 ticks at a time in the last queue
        return 0;
      }
      else {
        p->curq_ticks_left = MAX_TICKS_PER_QUEUE[3];
        p->curq_run = 0;
        return 1;
      }
    }
  }
  return 0;
}


// Give up the CPU for one scheduling round.
void
yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  if (mlfq_yield_helper(p) == 1) { //if no time slice left for process to continue
    // printf("YIELD TIMER INTERRUPT");
    // printf("\n\n\n\n");
    p->state = RUNNABLE;
    sched();
  } //otherwise let the process continue, yield will return in usertrap/kerneltrap and process will continue execution
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  // printf("SLEEP CONTEXT SWITCH");
  // printf("%d", ticks);
  // printf("\n\n\n\n");
  sched();   //we don't need to update any fields of process before the context switch

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void
wakeup(void *chan)   //processes will continue from their respective priority queue, not necessarily the topmost
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      acquire(&p->lock);
      if(p->state == SLEEPING && p->chan == chan) {
        p->state = RUNNABLE;

        if (p->curq < current_priority_queue) {  //if we are waking up a process which has a higher priority than the priority queue we were last executing in
            current_priority_queue = p->curq;
        }

      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        printf("killed %s",p->name);
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void
setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int
killed(struct proc *p)
{
  int k;
  
  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [USED]      "used",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}
