#include <parlib/common.h>
#include <futex.h>
#include <sys/queue.h>
#include <parlib/uthread.h>
#include <parlib/parlib.h>
#include <parlib/assert.h>
#include <stdio.h>
#include <errno.h>
#include <parlib/slab.h>
#include <parlib/mcs.h>
#include <parlib/alarm.h>

static inline int futex_wake(int *uaddr, int count);
static inline int futex_wait(int *uaddr, int val, uint64_t ms_timeout);
static void *timer_thread(void *arg);

struct futex_element {
  TAILQ_ENTRY(futex_element) link;
  struct uthread *uthread;
  int *uaddr;
  uint64_t us_timeout;
  struct alarm_waiter awaiter;
  bool timedout;
};
TAILQ_HEAD(futex_queue, futex_element);

struct futex_data {
  struct mcs_pdr_lock lock;
  struct futex_queue queue;
};
static struct futex_data __futex;

static inline void futex_init(void *arg)
{
  mcs_pdr_init(&__futex.lock);
  TAILQ_INIT(&__futex.queue);
}

static void __futex_timeout(struct alarm_waiter *awaiter) {
  struct futex_element *__e = NULL;
  struct futex_element *e = (struct futex_element*)awaiter->data;
  //printf("timeout fired: %p\n", e->uaddr);

  // Atomically remove the timed-out element from the futex queue if we won the
  // race against actually completing.
  mcs_pdr_lock(&__futex.lock);
  TAILQ_FOREACH(__e, &__futex.queue, link)
    if (__e == e) break;
  if (__e != NULL)
    TAILQ_REMOVE(&__futex.queue, e, link);
  mcs_pdr_unlock(&__futex.lock);

  // If we removed it, restart it outside the lock
  if (__e != NULL) {
    e->timedout = true;
    //printf("timeout: %p\n", e->uaddr);
    uthread_runnable(e->uthread);
  }
}

static void __futex_block(struct uthread *uthread, void *arg) {
  struct futex_element *e = (struct futex_element*)arg;

  // Set the remaining properties of the futex element
  e->uthread = uthread;
  e->timedout = false;

  // Insert the futex element into the queue
  TAILQ_INSERT_TAIL(&__futex.queue, e, link);

  // Set an alarm for the futex timeout if applicable
  if(e->us_timeout != (uint64_t)-1) {
    e->awaiter.data = e;
    init_awaiter(&e->awaiter, __futex_timeout);
    set_awaiter_rel(&e->awaiter, e->us_timeout);
    //printf("timeout set: %p\n", e->uaddr);
    set_alarm(&e->awaiter);
  }

  // Notify the scheduler of the type of yield we did
  uthread_has_blocked(uthread, UTH_EXT_BLK_MUTEX);

  // Unlock the pdr_lock 
  mcs_pdr_unlock(&__futex.lock);
}

static inline int futex_wait(int *uaddr, int val, uint64_t us_timeout)
{
  // Atomically do the following...
  mcs_pdr_lock(&__futex.lock);
  // If the value of *uaddr matches val
  if(*uaddr == val) {
    //printf("wait: %p, %d\n", uaddr, us_timeout);
    // Create a new futex element and initialize it.
    struct futex_element e;
    e.uaddr = uaddr;
    e.us_timeout = us_timeout;
    // Yield the uthread...
    // We set the remaining properties of the futex element, set the timeout
    // timer, and unlock the pdr lock on the other side.  It is important that
    // we do the unlock on the other side, because (unlike linux, etc.) its
    // possible to get interrupted and drop into vcore context right after
    // releasing the lock.  If that vcore code then calls futex_wake(), we
    // would be screwed.  Doing things this way means we have to hold the lock
    // longer, but its necessary for correctness.
    uthread_yield(TRUE, __futex_block, &e);
    // We are unlocked here!

	// Unset ensures the timeout won't happen, and if it did, that the alarm
	// service is done with the awaiter
    if(e.us_timeout != (uint64_t)-1)
	  unset_alarm(&e.awaiter);

    // After waking, if we timed out, set the error
    // code appropriately and return
    if(e.timedout) {
      errno = ETIMEDOUT;
      return -1;
    }
  } else {
      mcs_pdr_unlock(&__futex.lock);
  }
  return 0;
}

static inline int futex_wake(int *uaddr, int count)
{
  int max = count;
  struct futex_element *e,*n = NULL;
  struct futex_queue q = TAILQ_HEAD_INITIALIZER(q);

  // Atomically grab all relevant futex blockers
  // from the global futex queue
  mcs_pdr_lock(&__futex.lock);
  e = TAILQ_FIRST(&__futex.queue);
  while(e != NULL) {
    if(count > 0) {
      n = TAILQ_NEXT(e, link);
      if(e->uaddr == uaddr) {
        TAILQ_REMOVE(&__futex.queue, e, link);
        TAILQ_INSERT_TAIL(&q, e, link);
        count--;
      }
      e = n;
    }
    else break;
  }
  mcs_pdr_unlock(&__futex.lock);

  // Unblock them outside the lock
  e = TAILQ_FIRST(&q);
  while(e != NULL) {
    n = TAILQ_NEXT(e, link);
    TAILQ_REMOVE(&q, e, link);
    uthread_runnable(e->uthread);
    e = n;
  }
  return max-count;
}

int futex(int *uaddr, int op, int val,
          const struct timespec *timeout,
          int *uaddr2, int val3)
{
  static parlib_once_t once = PARLIB_ONCE_INIT;

  parlib_run_once(&once, futex_init, NULL);
  // Round to the nearest micro-second
  uint64_t us_timeout = (uint64_t)-1;
  assert(uaddr2 == NULL);
  assert(val3 == 0);
  if(timeout != NULL) {
    us_timeout = timeout->tv_sec*1000000L + timeout->tv_nsec/1000L;
    assert(us_timeout > 0);
  }
  switch(op) {
    case FUTEX_WAIT:
      return futex_wait(uaddr, val, us_timeout);
    case FUTEX_WAKE:
      return futex_wake(uaddr, val);
    default:
      errno = ENOSYS;
      return -1;
  }
  return -1;
}

