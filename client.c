#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <ioth.h>
#include <iothconf.h>
#include "iothconf_thread_dhcp.c"

#define UNBOUND -1
#define INIT 0
#define BOUND 1
#define RENEW 2
#define REBIND 3


int main(){
 	 
  unsigned int ifindex = 2;  //indice dell'interfaccia di rete che si vuole configurare 
  const char *fqdn = "host.v2.cs.unibo.it"; 
  uint32_t config_flags = 0;  
  
  //Create the stack
  struct ioth *stack = ioth_newstack("vdestack","vde:///tmp/mysw"); 

  
  int rv; 
  if( (rv = iothconf_dhcp(stack, ifindex, fqdn, config_flags)) < 0){
     printf("Errore client dhcp\n"); 
  }

  int check_times = 5;
  while(1){
    sleep(50);
    int status = -2;
    iothconf_dhcp_info(stack,ifindex,&status);
    switch(status){
        case UNBOUND :{
            printf("PADRE - TRHEAD STATUS UNBOUND CON STATUS CODE %d\n", status);
            break;
        };
        case INIT:{
            printf("PADRE - TRHEAD STATUS INIT CON STATUS CODE %d\n", status);
            break;
        };
        case BOUND:{
            printf("PADRE - TRHEAD STATUS BOUND CON STATUS CODE %d\n", status);
            break;
        };
        case RENEW:{
            printf("PADRE - TRHEAD STATUS RENEW CON STATUS CODE %d\n", status);
            break;
        };
        case REBIND:{
            printf("PADRE - TRHEAD STATUS REBIND CON STATUS CODE %d\n", status);
            break;
        };
        default :{
            printf(" STATUS CODE %d NON RICONOSCIUTO\n", status);
            break;
        }
    }
    if (check_times == 0) { 
        iothconf_dhcp_kill(stack, ifindex);
        return 0; 
    }else { check_times = check_times -1;} 
  }


  return 0; 
}
