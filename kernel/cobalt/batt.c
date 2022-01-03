#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>

#include <cobalt/kernel/pipe.h>

static RT_PIPE my_pipe;

#define XDDP_PORT 0     /* [0..CONFIG-XENO_OPT_PIPE_NRDEV - 1] */
#define MAX_BATT_READ_MSG_LENGTH 22 //TODO Add extra_size for battery_size + energy_production

Msg_battery battery_read_msg(void *arg)
{
  Msg_battery battery_message= {};

  //Non-blocking pipe read using TM_NONBLOCK (use TM_INFINITE to block indefinitely until some data..)
  if (rt_pipe_read( &my_pipe, buff,MAX_BATT_READ_MSG_LENGTH, TM_NONBLOCK) >= 0 )
  { 
      #if 0
        rt_printf("Reading message from nRT:%s\n",buff);
      #endif
      //Process message in struct
      sscanf((const char*)received_payload.data, "[%d,%d,%d]",
	(int*)&battery_message.capacity,
	(int*)&battery_message.chargenow,
	(int*)&battery_message.chargefull
	);

        /*TODO ADD:
        int battery_size;
        int energy_production;
        */
     
      if (battery_message.capacity >= 0 && 
        battery_message.chargenow >= 0 && battery_message.chargenow <= 100 &&
        battery_message.chargenow >= 0 && battery_message.chargenow <= 100)
      {
        battery_message.message_integrity = true;
      }

  }else{
    //Handle error
    battery_message.message_integrity = false;
  }

  return battery_message;
  
}

int batt_init (void)
{ 

  #if 0
    rt_print_auto_init(1);
  #endif
  rt_print_init(4096,str); 
  
  rt_pipe_delete(&my_pipe);
  if ( rt_pipe_create( &my_pipe, "rtp0", P_MINOR_AUTO, 0 ) != 0 )
  {
    rt_printf("rt_pipe_create error\n");
    return 1;
  }else{
    rt_printf("RT pipe create OK\n");
  }
  
  return 0;
}


int batt_deinit(void)
{

  rt_printf("Destroy RT pipe...\n");
  rt_pipe_delete(&my_pipe);

}
