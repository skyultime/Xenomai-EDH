#include <cobalt/kernel/batt.h>
#include <cobalt/kernel/assert.h>
#include <cobalt/kernel/heap.h>
#include <cobalt/kernel/bufd.h>
#include <cobalt/kernel/pipe.h>

#include <linux/module.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/time.h>

#include <rtdm/rtdm.h>
#include <rtdm/compat.h>
#include <rtdm/driver.h>
#include <rtdm/ipc.h>

#define XDDP_PORT 0     /* [0..CONFIG-XENO_OPT_PIPE_NRDEV - 1] */
#define MAX_BATT_READ_MSG_LENGTH 27

#define _XDDP_SYNCWAIT  0
#define _XDDP_ATOMIC    1
#define _XDDP_BINDING   2
#define _XDDP_BOUND     3
#define _XDDP_CONNECTED 4

/******************** STRUCT DEF ***************************/

struct rtipc_protocol;

struct rtipc_private {
	struct rtipc_protocol *proto;
	DECLARE_XNSELECT(send_block);
	DECLARE_XNSELECT(recv_block);
	void *state;
};

struct rtipc_protocol {
	const char *proto_name;
	int proto_statesz;
	int (*proto_init)(void);
	void (*proto_exit)(void);
	struct {
		int (*socket)(struct rtdm_fd *fd);
		void (*close)(struct rtdm_fd *fd);
		ssize_t (*recvmsg)(struct rtdm_fd *fd,
				   struct user_msghdr *msg, int flags);
		ssize_t (*sendmsg)(struct rtdm_fd *fd,
				   const struct user_msghdr *msg, int flags);
		ssize_t (*read)(struct rtdm_fd *fd,
				void *buf, size_t len);
		ssize_t (*write)(struct rtdm_fd *fd,
				 const void *buf, size_t len);
		int (*ioctl)(struct rtdm_fd *fd,
			     unsigned int request, void *arg);
		unsigned int (*pollstate)(struct rtdm_fd *fd);
	} proto_ops;
};

struct xddp_message {
	struct xnpipe_mh mh;
	char data[];
};

struct xddp_socket {
	int magic;
	struct sockaddr_ipc name;
	struct sockaddr_ipc peer;

	int minor;
	size_t poolsz;
	xnhandle_t handle;
	char label[XNOBJECT_NAME_LEN];
	struct rtdm_fd *fd;			/* i.e. RTDM socket fd */

	struct xddp_message *buffer;
	int buffer_port;
	struct xnheap *bufpool;
	struct xnheap privpool;
	size_t fillsz;
	size_t curbufsz;	/* Current streaming buffer size */
	u_long status;
	rtdm_lock_t lock;

	nanosecs_rel_t timeout;	/* connect()/recvmsg() timeout */
	size_t reqbufsz;	/* Requested streaming buffer size */

	int (*monitor)(struct rtdm_fd *fd, int event, long arg);
	struct rtipc_private *priv;
};

#ifdef CONFIG_XENO_OPT_VFILE
	static char *__xddp_link_target(void *obj)
	{
		struct xddp_socket *sk = obj;

		return kasformat("/dev/rtp%d", sk->minor);
	}

	extern struct xnptree rtipc_ptree;

	static struct xnpnode_link __xddp_pnode = {
		.node = {
			.dirname = "xddp",
			.root = &rtipc_ptree,
			.ops = &xnregistry_vlink_ops,
		},
		.target = __xddp_link_target,
	};
#else /* !CONFIG_XENO_OPT_VFILE */
	static struct xnpnode_link __xddp_pnode = {
		.node = {
			.dirname = "xddp",
		},
	};
#endif /* !CONFIG_XENO_OPT_VFILE */

/****************** END STRUCT DEF *************************/

static int batt_bind_socket(struct rtipc_private *priv,struct sockaddr_ipc *sa);

static int rtipc_get_sockaddr(struct rtdm_fd *fd, struct sockaddr_ipc **saddrp,
		       const void *arg);

static void *__xddp_alloc_handler(size_t size, void *skarg);
static void  __xddp_output_handler(struct xnpipe_mh *mh, void *skarg);

static int  __xddp_input_handler(struct xnpipe_mh *mh, int retval, void *skarg);
static void __xddp_free_handler(void *buf, void *skarg);
static void __xddp_release_handler(void *skarg);
static int  __xddp_resize_streambuf(struct xddp_socket *sk);

int __xddp_setsockopt(struct xddp_socket *sk,
			     struct rtdm_fd *fd,
			     void *arg);
int __xddp_getsockopt(struct xddp_socket *sk,
			     struct rtdm_fd *fd,
			     void *arg);

static struct rtdm_fd *portmap[CONFIG_XENO_OPT_PIPE_NRDEV]; /* indexes RTDM fildes */
static struct sockaddr_ipc saddr, *saddrp = &saddr;

Msg_battery battery_read_msg(void)
{
	
    Msg_battery battery_message= {};
    struct xnpipe_mh *mh;
    struct xddp_message *mbuf = NULL;	

	int ret = 0;
	ret = xnpipe_recv(saddrp->sipc_port,&mh,RTDM_TIMEOUT_NONE); 
     
    if(ret > MAX_BATT_READ_MSG_LENGTH){
      battery_message.message_integrity = false;
    }

	if (ret >= 0 )
	{ 
        
	    mbuf = container_of(mh, struct xddp_message, mh);

	    //Process message in struct
	    sscanf((const char*)mbuf->data, "[%d,%d,%d,%d,%d]",
			  (int*)&battery_message.capacity,
			  (int*)&battery_message.chargenow,
			  (int*)&battery_message.chargefull,
				(int*)&battery_message.battery_size,
	      (int*)&battery_message.energy_production
	);
	   
	    if (battery_message.capacity >= 0 && 
	      battery_message.chargenow >= 0 && battery_message.chargenow <= 100 &&
	      battery_message.chargenow >= 0 && battery_message.chargenow <= 100 &&
	battery_message.battery_size >= 0 && battery_message.chargenow <= BATTERY_SIZE_MAX_VALUE &&
	      battery_message.energy_production >= 0 && battery_message.energy_production <= EP_MAX_VALUE
	       )
	    {
	      battery_message.message_integrity = true;
	    }

	}else{
	  //Handle error
	  battery_message.message_integrity = false;
	}

    return battery_message;
}

int batt_init (void){ 	

    int ret  = 0;
    
    struct rtdm_fd *fd; //TODO
    const struct _rtdm_setsockaddr_args *arg; //TODO : https://xenomai.org/documentation/xenomai-3/html/xeno3prm/xddp-stream_8c-example.html

    //TODO Set buffsize to 1024 bytes

    struct rtipc_private *priv = rtdm_fd_to_private(fd);

    ret = rtipc_get_sockaddr(fd, &saddrp, arg);

    if (ret)
      return ret;

    if (saddrp == NULL )
      return -EFAULT;

    #ifdef USE_AUTO_SELECT
      //Nothing to do
    #else
      saddrp->sipc_port = XDDP_PORT;
    #endif
    saddrp->sipc_family = AF_RTIPC;    

    ret = batt_bind_socket(priv,saddrp);

    if(ret < 0)
    {
      printk(XENO_INFO "xddp_pipe_create error\n");
      return 1;
    }else{
      printk(XENO_INFO "XDDP pipe create OK\n");
    }
  
  return 0;
}

int batt_bind_socket(struct rtipc_private *priv,struct sockaddr_ipc *sa){
	struct xddp_socket *sk = priv->state;
	struct xnpipe_operations ops;
	rtdm_lockctx_t s;
	size_t poolsz;
	void *poolmem;
	int ret = 0;

	if (sa->sipc_family != AF_RTIPC)
		return -EINVAL;

	/* Allow special port -1 for auto-selection. */
	if (sa->sipc_port < -1 ||
	    sa->sipc_port >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -EINVAL;

	cobalt_atomic_enter(s);
	if (test_bit(_XDDP_BOUND, &sk->status) ||
	    __test_and_set_bit(_XDDP_BINDING, &sk->status))
		ret = -EADDRINUSE;
	cobalt_atomic_leave(s);
	if (ret)
		return ret;

	poolsz = sk->poolsz;
	if (poolsz > 0) {
		poolsz = PAGE_ALIGN(poolsz);
		poolsz += PAGE_ALIGN(sk->reqbufsz);
		poolmem = xnheap_vmalloc(poolsz);
		if (poolmem == NULL) {
			ret = -ENOMEM;
			goto fail;
		}

		ret = xnheap_init(&sk->privpool, poolmem, poolsz);
		if (ret) {
			xnheap_vfree(poolmem);
			goto fail;
		}

		sk->bufpool = &sk->privpool;
	} else
		sk->bufpool = &cobalt_heap;

	if (sk->reqbufsz > 0) {
		sk->buffer = xnheap_alloc(sk->bufpool, sk->reqbufsz);
		if (sk->buffer == NULL) {
			ret = -ENOMEM;
			goto fail_freeheap;
		}
		sk->curbufsz = sk->reqbufsz;
	}

	sk->fd = rtdm_private_to_fd(priv);

	ops.output = &__xddp_output_handler;
	ops.input = &__xddp_input_handler;
	ops.alloc_ibuf = &__xddp_alloc_handler;
	ops.free_ibuf = &__xddp_free_handler;
	ops.free_obuf = &__xddp_free_handler;
	ops.release = &__xddp_release_handler;

	// sa->sipc_port = -1 to find and pick the next free minor
	ret = xnpipe_connect(sa->sipc_port, &ops, sk); 
	if (ret < 0) {
		if (ret == -EBUSY)
			ret = -EADDRINUSE;
	fail_freeheap:
		if (poolsz > 0) {
			xnheap_destroy(&sk->privpool);
			xnheap_vfree(poolmem);
		}
	fail:
		clear_bit(_XDDP_BINDING, &sk->status);
		return ret;
	}

	sk->minor = ret;
	sa->sipc_port = ret;
	sk->name = *sa;

	/* Set default destination if unset at binding time. */
	if (sk->peer.sipc_port < 0)
		sk->peer = *sa;

	if (poolsz > 0)
		xnheap_set_name(sk->bufpool, "xddp-pool@%d", sa->sipc_port);

	if (*sk->label) {
		ret = xnregistry_enter(sk->label, sk, &sk->handle,
				       &__xddp_pnode.node);
		if (ret) {
			/* The release handler will cleanup the pool for us. */
			xnpipe_disconnect(sk->minor);
			return ret;
		}
	}

	cobalt_atomic_enter(s);
	portmap[sk->minor] = rtdm_private_to_fd(priv);
	__clear_bit(_XDDP_BINDING, &sk->status);
	__set_bit(_XDDP_BOUND, &sk->status);
	if (xnselect_signal(&priv->send_block, POLLOUT))
		xnsched_run();
	cobalt_atomic_leave(s);

        //Here, binding ok at addr /dev/rtp 'sk->minor'
	return 0;	

}

int batt_deinit(void){

  xnpipe_disconnect(saddrp->sipc_port);
  printk(XENO_INFO "Destroy XDDP pipe...\n");
  
  return 0;
}

/************************** RTIPC *************************************/

int rtipc_get_sockaddr(struct rtdm_fd *fd, struct sockaddr_ipc **saddrp,
		       const void *arg){

	const struct _rtdm_setsockaddr_args *p;
	struct _rtdm_setsockaddr_args sreq;
	int ret;

	if (!rtdm_fd_is_user(fd)) {
		p = arg;
		if (p->addrlen > 0) {
			if (p->addrlen != sizeof(**saddrp))
				return -EINVAL;
			memcpy(*saddrp, p->addr, sizeof(**saddrp));
		} else {
			if (p->addr)
				return -EINVAL;
			*saddrp = NULL;
		}
		return 0;
	}

#ifdef CONFIG_XENO_ARCH_SYS3264
	if (rtdm_fd_is_compat(fd)) {
		struct compat_rtdm_setsockaddr_args csreq;
		ret = rtdm_safe_copy_from_user(fd, &csreq, arg, sizeof(csreq));
		if (ret)
			return ret;
		if (csreq.addrlen > 0) {
			if (csreq.addrlen != sizeof(**saddrp))
				return -EINVAL;
			return rtdm_safe_copy_from_user(fd, *saddrp,
							compat_ptr(csreq.addr),
							sizeof(**saddrp));
		}
		if (csreq.addr)
			return -EINVAL;

		*saddrp = NULL;

		return 0;
	}
#endif

	ret = rtdm_safe_copy_from_user(fd, &sreq, arg, sizeof(sreq));
	if (ret)
		return ret;
	if (sreq.addrlen > 0) {
		if (sreq.addrlen != sizeof(**saddrp))
			return -EINVAL;
		return rtdm_safe_copy_from_user(fd, *saddrp,
						sreq.addr, sizeof(**saddrp));
	}
	if (sreq.addr)
		return -EINVAL;

	*saddrp = NULL;

	return 0;
}

/************************** XDDP *************************************/

void __xddp_free_handler(void *buf, void *skarg){ /* nklock free */

	struct xddp_socket *sk = skarg;
	rtdm_lockctx_t s;

	if (buf != sk->buffer) {
		xnheap_free(sk->bufpool, buf);
		return;
	}

	/* Reset the streaming buffer. */

	rtdm_lock_get_irqsave(&sk->lock, s);

	sk->fillsz = 0;
	sk->buffer_port = -1;
	__clear_bit(_XDDP_SYNCWAIT, &sk->status);
	__clear_bit(_XDDP_ATOMIC, &sk->status);

	/*
	 * If a XDDP_BUFSZ request is pending, resize the streaming
	 * buffer on-the-fly.
	 */
	if (unlikely(sk->curbufsz != sk->reqbufsz))
		__xddp_resize_streambuf(sk);

	rtdm_lock_put_irqrestore(&sk->lock, s);
}

int __xddp_input_handler(struct xnpipe_mh *mh, int retval, void *skarg){ /* nklock held */

	struct xddp_socket *sk = skarg;

	if (sk->monitor) {
		if (retval == 0)
			/* Callee may alter the return value passed to userland. */
			retval = sk->monitor(sk->fd, XDDP_EVTIN, xnpipe_m_size(mh));
		else if (retval == -EPIPE && mh == NULL)
			sk->monitor(sk->fd, XDDP_EVTDOWN, 0);
	}

	if (retval == 0 &&
	    (__xnpipe_pollstate(sk->minor) & POLLIN) != 0 &&
	    xnselect_signal(&sk->priv->recv_block, POLLIN))
		xnsched_run();

	return retval;
}

void __xddp_output_handler(struct xnpipe_mh *mh, void *skarg){ /* nklock held */

	struct xddp_socket *sk = skarg;

	if (sk->monitor)
		sk->monitor(sk->fd, XDDP_EVTOUT, xnpipe_m_size(mh));
}

void *__xddp_alloc_handler(size_t size, void *skarg){ /* nklock free */

	struct xddp_socket *sk = skarg;
	void *buf;

	/* Try to allocate memory for the incoming message. */
	buf = xnheap_alloc(sk->bufpool, size);
	if (unlikely(buf == NULL)) {
		if (sk->monitor)
			sk->monitor(sk->fd, XDDP_EVTNOBUF, size);
		if (size > xnheap_get_size(sk->bufpool))
			buf = (void *)-1; /* Will never succeed. */
	}

	return buf;
}

void __xddp_release_handler(void *skarg){ /* nklock free */

	struct xddp_socket *sk = skarg;
	void *poolmem;
	u32 poolsz;

	if (sk->bufpool == &sk->privpool) {
		poolmem = xnheap_get_membase(&sk->privpool);
		poolsz = xnheap_get_size(&sk->privpool);
		xnheap_destroy(&sk->privpool);
		xnheap_vfree(poolmem);
	} else if (sk->buffer)
		xnfree(sk->buffer);

	kfree(sk);
}

int __xddp_resize_streambuf(struct xddp_socket *sk){ /* sk->lock held */
	if (sk->buffer)
		xnheap_free(sk->bufpool, sk->buffer);

	if (sk->reqbufsz == 0) {
		sk->buffer = NULL;
		sk->curbufsz = 0;
		return 0;
	}

	sk->buffer = xnheap_alloc(sk->bufpool, sk->reqbufsz);
	if (sk->buffer == NULL) {
		sk->curbufsz = 0;
		return -ENOMEM;
	}

	sk->curbufsz = sk->reqbufsz;

	return 0;
}

int __xddp_setsockopt(struct xddp_socket *sk,
			     struct rtdm_fd *fd,
			     void *arg)
{
	int (*monitor)(struct rtdm_fd *fd, int event, long arg);
	struct _rtdm_setsockopt_args sopt;
	struct rtipc_port_label plabel;
	struct __kernel_old_timeval tv;
	rtdm_lockctx_t s;
	size_t len;
	int ret;

	ret = rtipc_get_sockoptin(fd, &sopt, arg);
	if (ret)
		return ret;

	if (sopt.level == SOL_SOCKET) {
		switch (sopt.optname) {

		case SO_RCVTIMEO_OLD:
			ret = rtipc_get_timeval(fd, &tv, sopt.optval, sopt.optlen);
			if (ret)
				return ret;
			sk->timeout = rtipc_timeval_to_ns(&tv);
			break;

		default:
			ret = -EINVAL;
		}

		return ret;
	}

	if (sopt.level != SOL_XDDP)
		return -ENOPROTOOPT;

	switch (sopt.optname) {

	case XDDP_BUFSZ:
		ret = rtipc_get_length(fd, &len, sopt.optval, sopt.optlen);
		if (ret)
			return ret;
		if (len > 0) {
			len += sizeof(struct xddp_message);
			if (sk->bufpool &&
			    len > xnheap_get_size(sk->bufpool)) {
				return -EINVAL;
			}
		}
		rtdm_lock_get_irqsave(&sk->lock, s);
		sk->reqbufsz = len;
		if (len != sk->curbufsz &&
		    !test_bit(_XDDP_SYNCWAIT, &sk->status) &&
		    test_bit(_XDDP_BOUND, &sk->status))
			ret = __xddp_resize_streambuf(sk);
		rtdm_lock_put_irqrestore(&sk->lock, s);
		break;

	case XDDP_POOLSZ:
		ret = rtipc_get_length(fd, &len, sopt.optval, sopt.optlen);
		if (ret)
			return ret;
		if (len == 0)
			return -EINVAL;
		cobalt_atomic_enter(s);
		if (test_bit(_XDDP_BOUND, &sk->status) ||
		    test_bit(_XDDP_BINDING, &sk->status))
			ret = -EALREADY;
		else
			sk->poolsz = len;
		cobalt_atomic_leave(s);
		break;

	case XDDP_MONITOR:
		/* Monitoring is available from kernel-space only. */
		if (rtdm_fd_is_user(fd))
			return -EPERM;
		if (sopt.optlen != sizeof(monitor))
			return -EINVAL;
		if (rtipc_get_arg(NULL, &monitor, sopt.optval, sizeof(monitor)))
			return -EFAULT;
		sk->monitor = monitor;
		break;

	case XDDP_LABEL:
		if (sopt.optlen < sizeof(plabel))
			return -EINVAL;
		if (rtipc_get_arg(fd, &plabel, sopt.optval, sizeof(plabel)))
			return -EFAULT;
		cobalt_atomic_enter(s);
		if (test_bit(_XDDP_BOUND, &sk->status) ||
		    test_bit(_XDDP_BINDING, &sk->status))
			ret = -EALREADY;
		else {
			strcpy(sk->label, plabel.label);
			sk->label[XNOBJECT_NAME_LEN-1] = 0;
		}
		cobalt_atomic_leave(s);
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

int __xddp_getsockopt(struct xddp_socket *sk,
			     struct rtdm_fd *fd,
			     void *arg)
{
	struct _rtdm_getsockopt_args sopt;
	struct rtipc_port_label plabel;
	struct __kernel_old_timeval tv;
	rtdm_lockctx_t s;
	socklen_t len;
	int ret;

	ret = rtipc_get_sockoptout(fd, &sopt, arg);
	if (ret)
		return ret;

	if (rtipc_get_arg(fd, &len, sopt.optlen, sizeof(len)))
		return -EFAULT;

	if (sopt.level == SOL_SOCKET) {
		switch (sopt.optname) {

		case SO_RCVTIMEO_OLD:
			rtipc_ns_to_timeval(&tv, sk->timeout);
			ret = rtipc_put_timeval(fd, sopt.optval, &tv, len);
			if (ret)
				return ret;
			break;

		default:
			ret = -EINVAL;
		}

		return ret;
	}

	if (sopt.level != SOL_XDDP)
		return -ENOPROTOOPT;

	switch (sopt.optname) {

	case XDDP_LABEL:
		if (len < sizeof(plabel))
			return -EINVAL;
		cobalt_atomic_enter(s);
		strcpy(plabel.label, sk->label);
		cobalt_atomic_leave(s);
		if (rtipc_put_arg(fd, sopt.optval, &plabel, sizeof(plabel)))
			return -EFAULT;
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

