/*
 * Copyright (C) 2008 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

/**
 * @addtogroup cobalt_core_sched
 * @{
 */

#ifndef _COBALT_KERNEL_SCHED_DYNA_H
#define _COBALT_KERNEL_SCHED_DYNA_H

#ifndef _COBALT_KERNEL_SCHED_H
#error "please don't include cobalt/kernel/sched-dyna.h directly"
#endif

extern struct xnsched_class xnsched_class_dyna;

static inline void __xnsched_dyna_requeue(struct xnthread *thread)
{
	xnsched_dyna_addq(&thread->sched->dyna.runnable, thread);
}

static inline void __xnsched_dyna_enqueue(struct xnthread *thread)
{
	xnsched_dyna_addq_tail(&thread->sched->dyna.runnable, thread);
}

static inline void __xnsched_dyna_dequeue(struct xnthread *thread)
{
	xnsched_delq(&thread->sched->dyna.runnable, thread);
}

static inline void __xnsched_dyna_track_weakness(struct xnthread *thread)
{
	/*
	 * We have to track threads exiting weak scheduling, i.e. any
	 * thread leaving the WEAK class code if compiled in, or
	 * assigned a zero priority if weak threads are hosted by the
	 * RT class.
	 *
	 * CAUTION: since we need to check the effective priority
	 * level for determining the weakness state, this can only
	 * apply to non-boosted threads.
	 */
	if (IS_ENABLED(CONFIG_XENO_OPT_SCHED_WEAK) || thread->cprio)
		xnthread_clear_state(thread, XNWEAK);
	else
		xnthread_set_state(thread, XNWEAK);
}

static inline bool __xnsched_dyna_setparam(struct xnthread *thread,
					 const union xnsched_policy_param *p)
{	
	thread->next_deadline = p->rt.deadline;

	if (!xnthread_test_state(thread, XNBOOST))
		__xnsched_dyna_track_weakness(thread);

	return false;
}

static inline void __xnsched_dyna_getparam(struct xnthread *thread,
					 union xnsched_policy_param *p)
{
	p->rt.deadline = thread->next_deadline;
}

static inline void __xnsched_dyna_trackprio(struct xnthread *thread,
					  const union xnsched_policy_param *p)
{
	if (p)
		thread->cprio = p->rt.prio; /* Force update. */
	else {
		thread->cprio = thread->bprio;
		/* Leaving PI/PP, so non-boosted by definition. */
		__xnsched_dyna_track_weakness(thread);
	}
}

static inline void __xnsched_dyna_protectprio(struct xnthread *thread, int prio)
{
	/*
	 * The RT class supports the widest priority range from
	 * XNSCHED_CORE_MIN_PRIO to XNSCHED_CORE_MAX_PRIO inclusive,
	 * no need to cap the input value which is guaranteed to be in
	 * the range [1..XNSCHED_CORE_MAX_PRIO].
	 */
	thread->cprio = prio;
}

static inline void __xnsched_dyna_forget(struct xnthread *thread)
{
}

static inline int xnsched_dyna_init_thread(struct xnthread *thread)
{
	return 0;
}

#ifdef CONFIG_XENO_OPT_SCHED_CLASSES
struct xnthread *xnsched_rt_pick(struct xnsched *sched);
#else
static inline struct xnthread *xnsched_dyna_pick(struct xnsched *sched)
{
	return xnsched_getq(&sched->rt.runnable);
}
#endif

void xnsched_dyna_tick(struct xnsched *sched);

#endif
