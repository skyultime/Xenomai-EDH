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

#if 0
  #include <sys/select.h>
  #include <linux/fcntl.h>
#endif

#define XDDP_PORT 0     /* [0..CONFIG-XENO_OPT_PIPE_NRDEV - 1] */
#define MAX_BATT_READ_MSG_LENGTH 27

static void rt_batt_loop(void *arg);

/* Thread for transmission */
static rtdm_task_t rt_batt_task;

static int ufd = 0;

Msg_battery battery_read_msg(void)
{
	char buf[128];
    struct timespec ts;
    fd_set readfds; 
    Msg_battery battery_message= {};
    int ret = 0,ret_select = 0;

    #if 0
	  fcntl(ufd, F_SETFL, O_NONBLOCK);    

    //TODO Warning : blocking call here... Need to use select
    ts.tv_sec = 0;
    ts.tv_nsec = 0; /* 0 ms */

    ret_select = select(ufd + 1, &readfds, NULL, NULL, &ts); 
    	
    if (ret_select ==1)
      ret = rtdm_recvfrom(ufd, buf, MAX_BATT_READ_MSG_LENGTH, 0, NULL, 0);
    #endif

    ret = rtdm_read(ufd, buf, MAX_BATT_READ_MSG_LENGTH);    

    if(ret > MAX_BATT_READ_MSG_LENGTH){
      battery_message.message_integrity = false;
    }

	if (ret >= 0 )
	{ 

	    //Process message in struct
	    sscanf((const char*)buf, "[%d,%d,%d,%d,%d]",
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

    int err  =0;

    /* Init the task */
    err = rtdm_task_init(&rt_batt_task, "rt_batt_init",
     	rt_batt_loop, 0, RTDM_TASK_LOWEST_PRIORITY,
     	0);

    printk(XENO_INFO "batt_init OK\n");	
	
    return err;
}

void rt_batt_loop(void *arg){

    struct sockaddr_ipc saddr;
    int ret;
    size_t poolsz;

    printk("XENO_WARNING Enter rt_batt_loop section\n");    

    /*
     * Get a datagram socket to bind to the RT endpoint. Each
     * endpoint is represented by a port number within the XDDP
     * protocol namespace.
     */
        
    ufd = __rtdm_dev_socket(AF_RTIPC, SOCK_DGRAM, IPCPROTO_XDDP);
    if (ufd < 0) {
		printk("XENO_WARNING __rtdm_dev_socket failed\n");
    }
    /*
     * Set a local 16k pool for the RT endpoint. Memory needed to
     * convey datagrams will be pulled from this pool, instead of
     * Xenomai's system pool.
     */
    poolsz = 16384; /* bytes */
    ret = rtdm_setsockopt(ufd, SOL_XDDP, XDDP_POOLSZ,
                     &poolsz, sizeof(poolsz));
    if (ret)
            printk("XENO_WARNING setsockopt failed\n");
    /*
     * Bind the socket to the port, to setup a proxy to channel
     * traffic to/from the Linux domain.
     *
     * saddr.sipc_port specifies the port number to use.
     */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sipc_family = AF_RTIPC;
    saddr.sipc_port = XDDP_PORT;
    ret = rtdm_bind(ufd, (struct sockaddr *)&saddr, sizeof(saddr));

	if(ret < 0)
	{
	  printk(XENO_INFO "bind error\n");
	}else{
	  printk(XENO_INFO "bind OK on port %d\n",XDDP_PORT);
	}

}

int batt_deinit(void){

  rtdm_close(ufd);
  rtdm_task_destroy(&rt_batt_task);
  printk(XENO_INFO "Destroy socket...\n");
  
  return 0;
}
