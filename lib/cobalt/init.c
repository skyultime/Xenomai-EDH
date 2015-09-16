/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <semaphore.h>
#include <boilerplate/setup.h>
#include <cobalt/uapi/kernel/heap.h>
#include <cobalt/ticks.h>
#include <cobalt/tunables.h>
#include <asm/xenomai/syscall.h>
#include <xenomai/init.h>
#include "umm.h"
#include "internal.h"

/**
 * @ingroup cobalt
 * @defgroup cobalt_api POSIX interface
 *
 * The Cobalt/POSIX interface is an implementation of a subset of the
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/">
 * Single Unix specification</a> over the Cobalt core.
 */

__weak int __cobalt_control_bind = 0;

int __cobalt_main_prio = -1;

struct sigaction __cobalt_orig_sigdebug;

static const struct option cobalt_options[] = {
	{
#define main_prio_opt		0
		.name = "main-prio",
		.has_arg = 1,
	},
	{
#define print_bufsz_opt	1
		.name = "print-buffer-size",
		.has_arg = 1,
	},
	{
#define print_bufcnt_opt	2
		.name = "print-buffer-count",
		.has_arg = 1,
	},
	{
#define print_syncdelay_opt	3
		.name = "print-sync-delay",
		.has_arg = 1,
	},
	{
		/* sentinel */
	}
};

static void sigill_handler(int sig)
{
	const char m[] = "no Xenomai/cobalt support in kernel?\n";
	ssize_t rc __attribute__ ((unused));
	rc = write(2, m, sizeof(m) - 1);
	exit(EXIT_FAILURE);
}

static void low_init(void)
{
	sighandler_t old_sigill_handler;
	struct cobalt_bindreq breq;
	struct cobalt_featinfo *f;
	int ret;

	old_sigill_handler = signal(SIGILL, sigill_handler);
	if (old_sigill_handler == SIG_ERR)
		early_panic("signal(SIGILL): %s", strerror(errno));

	f = &breq.feat_ret;
	breq.feat_req = XENOMAI_FEAT_DEP;
	if (__cobalt_control_bind)
		breq.feat_req |= __xn_feat_control;
	breq.abi_rev = XENOMAI_ABI_REV;
	ret = XENOMAI_SYSBIND(&breq);

	signal(SIGILL, old_sigill_handler);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		early_panic("missing feature: %s", f->feat_mis_s);
	case -ENOEXEC:
		early_panic("ABI mismatch: required r%lu, provided r%lu",
			    XENOMAI_ABI_REV, f->feat_abirev);
	default:
		early_panic("binding failed: %s", strerror(-ret));
	}

	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		early_panic("mlockall: %s", strerror(errno));

	cobalt_check_features(f);
	cobalt_init_umm(f->vdso_offset);
	cobalt_init_current_keys();
	cobalt_ticks_init(f->clock_freq);
}

static void cobalt_fork_handler(void)
{
	cobalt_unmap_umm();
	cobalt_clear_tsd();
	cobalt_print_init_atfork();
	if (cobalt_init())
		exit(EXIT_FAILURE);
}

static void __cobalt_init(void)
{
	struct sigaction sa;

	low_init();

	sa.sa_sigaction = cobalt_sigdebug_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGDEBUG, &sa, &__cobalt_orig_sigdebug);

	/*
	 * NOTE: a placeholder for pthread_atfork() may return an
	 * error status with uClibc, so we don't check the return
	 * value on purpose.
	 */
	pthread_atfork(NULL, NULL, cobalt_fork_handler);

	if (sizeof(struct cobalt_mutex_shadow) > sizeof(pthread_mutex_t))
		early_panic("sizeof(pthread_mutex_t): %Zd <"
			    " sizeof(cobalt_mutex_shadow): %Zd!",
			    sizeof(pthread_mutex_t),
			    sizeof(struct cobalt_mutex_shadow));

	if (sizeof(struct cobalt_cond_shadow) > sizeof(pthread_cond_t))
		early_panic("sizeof(pthread_cond_t): %Zd <"
			    " sizeof(cobalt_cond_shadow): %Zd!",
			    sizeof(pthread_cond_t),
			    sizeof(struct cobalt_cond_shadow));

	if (sizeof(struct cobalt_sem_shadow) > sizeof(sem_t))
		early_panic("sizeof(sem_t): %Zd <"
			    " sizeof(cobalt_sem_shadow): %Zd!",
			    sizeof(sem_t),
			    sizeof(struct cobalt_sem_shadow));

	cobalt_thread_init();
	cobalt_print_init();
}

static inline void commit_stack_memory(void)
{
	char stk[PTHREAD_STACK_MIN / 2];
	cobalt_commit_memory(stk);
}

int cobalt_init(void)
{
	pthread_t ptid = pthread_self();
	struct sched_param parm;
	int policy, ret;

	commit_stack_memory();	/* We only need this for the main thread */
	cobalt_default_mutexattr_init();
	cobalt_default_condattr_init();
	__cobalt_init();

	if (__cobalt_control_bind)
		return 0;

	ret = __STD(pthread_getschedparam(ptid, &policy, &parm));
	if (ret) {
		early_warning("pthread_getschedparam failed");
		return -ret;
	}

	/*
	 * Switch the main thread to a Xenomai shadow.
	 * __cobalt_main_prio might have been overriden by
	 * some compilation unit which has been linked in, to force
	 * the scheduling parameters. Otherwise, the current policy
	 * and priority are reused, for declaring the thread to the
	 * Xenomai scheduler.
	 *
	 * SCHED_FIFO is assumed for __cobalt_main_prio > 0.
	 */
	if (__cobalt_main_prio > 0) {
		policy = SCHED_FIFO;
		parm.sched_priority = __cobalt_main_prio;
	} else if (__cobalt_main_prio == 0) {
		policy = SCHED_OTHER;
		parm.sched_priority = 0;
	}

	ret = __RT(pthread_setschedparam(ptid, policy, &parm));
	if (ret) {
		early_warning("pthread_setschedparam failed (prio=%d)",
			__cobalt_main_prio);
		return -ret;
	}

	return 0;
}

static int get_int_arg(const char *name, const char *arg,
		       int *valp, int min)
{
	int value, ret;
	char *p;
	
	errno = 0;
	value = (int)strtol(arg, &p, 10);
	if (errno || *p || value < min) {
		ret = -errno ?: -EINVAL;
		early_warning("invalid value for %s: %s", name, arg);
		return ret;
	}

	*valp = value;

	return 0;
}

static int cobalt_parse_option(int optnum, const char *optarg)
{
	int value, ret;

	switch (optnum) {
	case main_prio_opt:
		ret = get_int_arg("--main-prio", optarg, &value, INT32_MIN);
		if (ret)
			return ret;
		__cobalt_main_prio = value;
		break;
	case print_bufsz_opt:
		ret = get_int_arg("--print-buffer-size", optarg, &value, 0);
		if (ret)
			return ret;
		__cobalt_print_bufsz = value;
		break;
	case print_bufcnt_opt:
		ret = get_int_arg("--print-buffer-count", optarg, &value, 0);
		if (ret)
			return ret;
		__cobalt_print_bufcount = value;
		break;
	case print_syncdelay_opt:
		ret = get_int_arg("--print-sync-delay", optarg, &value, 0);
		if (ret)
			return ret;
		__cobalt_print_syncdelay = value;
		break;
	default:
		/* Paranoid, can't happen. */
		return -EINVAL;
	}

	return 0;
}

static void cobalt_help(void)
{
        fprintf(stderr, "--main-prio=<prio>		main thread priority\n");
        fprintf(stderr, "--print-buffer-size=<bytes>	size of a print relay buffer (16k)\n");
        fprintf(stderr, "--print-buffer-count=<num>	number of print relay buffers (4)\n");
        fprintf(stderr, "--print-buffer-syncdelay=<ms>	max delay of output synchronization (100 ms)\n");
}

static struct setup_descriptor cobalt_interface = {
	.name = "cobalt",
	.init = cobalt_init,
	.options = cobalt_options,
	.parse_option = cobalt_parse_option,
	.help = cobalt_help,
};

core_setup_call(cobalt_interface);
