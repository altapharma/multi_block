#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* IP header */
  struct sniff_ip {
    u_char ip_vhl;    /* version << 4 | header length >> 2 */
    u_char ip_tos;    /* type of service */
    u_short ip_len;   /* total length */
    u_short ip_id;    /* identification */
    u_short ip_off;   /* fragment offset field */
  	#define IP_RF 0x8000    /* reserved fragment flag */
  	#define IP_DF 0x4000    /* dont fragment flag */
  	#define IP_MF 0x2000    /* more fragments flag */
  	#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl;    /* time to live */
    u_char ip_p;    /* protocol */
    u_short ip_sum;   /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
  };
  #define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f) //ip_vhl = ip_version(4bit) + ip_header_length(4bit) 
  #define IP_V(ip)    (((ip)->ip_vhl) >> 4)
//----------------------------------------------------------------------------------//

  /* TCP header */
  typedef u_int tcp_seq;

  struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
  	#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)  //th_off(8bit) = data_offset(4bit) + reserved(3bit) 
    u_char th_flags;
  	#define TH_FIN 0x01
  	#define TH_SYN 0x02
  	#define TH_RST 0x04
  	#define TH_PUSH 0x08
  	#define TH_ACK 0x10
  	#define TH_URG 0x20
  	#define TH_ECE 0x40
 	#define TH_CWR 0x80
  	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;   /* window */
    u_short th_sum;   /* checksum */
    u_short th_urp;   /* urgent pointer */
};
//----------------------------------------------------------------------------------//

//make url stack

typedef struct _node{
  char* url;
  struct _node* next;
}node;

typedef node* nptr;

typedef struct _list{
  int count;
  nptr head;
}list;

void init(list* lptr);
void insert(list* lptr,char* url);
int search(list* lptr,char* url);

void init(list* lptr){
  //initialize the list
  lptr->count=0;
  lptr->head=NULL;
}

void insert(list* lptr,char* url){
  nptr new_nptr=(node*)malloc(sizeof(node));
  new_nptr->url = (char*)malloc(sizeof(char)*100);
  strcpy(new_nptr->url,url);
  new_nptr->next = lptr->head;
  lptr->head=new_nptr;
  
  lptr->count++;
}
//need modification
int search(list* lptr,char* url){
  nptr tmp=lptr->head;
  int i=1;
  while(tmp!=NULL){
    if(!strcmp(url,tmp->url)) break;
    i++;
    tmp=tmp->next;
  }
  if(i>lptr->count){
    return 0;
  }
  else{
    return 1;
  }
}