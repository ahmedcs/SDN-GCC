#ifndef EVILBIT_H
#define EVITBIT_H 1

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <net/pkt_sched.h>
#include <linux/openvswitch.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

//#include "rwndq.h"
//#include "myflow.h"


/******************************************Ahmed***********************************************/
#define MY_GSO_MAX_SIZE  8 * 1024
#define g 4
#define TCP_FLAGS_BE16(tp) (*(__be16 *)&tcp_flag_word(tp) & htons(0x0FFF))
#define track_TBL_MIN_BUCKETS     100 //1024
#define track_CHECK_INTERVAL (1 * HZ) // 1 seconds check
#define track_FLOW_LIFE (5 * HZ) // not active for 5 secs will be removed

#define IDLE_TIMEOUT_US (100 * 1000 * 10 * 1000)
#define IDLE_RATE (100) //100 Mb/s
#define ECN_REFLECT_MASK (1 << 3)

/* Rate size within 1 interval */
#define DEFAULT_CAPACITY 125000 // for burst within 1 ms

void add_evil_connection(const struct net_device * dev, __be32 addr);
void del_evil_connection(const struct net_device * dev);
void add_evil_dev(const struct net_device * dev,  bool isvirt, __be32 addr);
void del_evil_dev(const struct net_device * dev,  bool isvirt);
enum hrtimer_restart evil_timer_callback(struct hrtimer *timer);
void evil_process(struct sk_buff *skb,  struct vport *inp , struct vport *outp, struct sw_flow_key *key);
void init_evil(void);
void cleanup_evil(void);
void init_variables(void);
void init_ethdevices(void);
void  reset_ethdevices(void);
void refill_tokens(void);
/******************************************Ahmed***********************************************/

/****************************************ECN*************************************************/
static inline void enable_evil(struct iphdr *iph)
{
    iph->frag_off|=htons(IP_CE);
    //Recalculate IP checksum
    iph->check=0;
    iph->check=ip_fast_csum(iph,iph->ihl);
}

static inline void clear_evil(struct iphdr *iph)
{
    iph->frag_off &= ~htons(IP_CE);
    //Recalculate IP checksum
    iph->check=0;
    iph->check=ip_fast_csum(iph,iph->ihl);
}

static inline void enable_ecn(struct iphdr *iph)
{
    ipv4_change_dsfield(iph, 0xff, iph->tos | INET_ECN_ECT_0);
}

static inline void clear_ecn(struct iphdr *iph)
{
    ipv4_change_dsfield(iph, 0xff, iph->tos & ~0x3);
}

/****************************************ECN*************************************************/

/************************************Feedback***********************************************/

/**********************feedback variables************************/
// We are assuming that we don't need to do any VLAN tag
const int extern FEEDBACK_INTERVAL_US;
const int extern FEEDBACK_INTERVAL_MARKS;

// TODO: We are assuming that we don't need to do any VLAN tag
// ourselves
const int extern FEEDBACK_PACKET_SIZE ;
const u16 extern FEEDBACK_HEADER_SIZE;
const u8 extern FEEDBACK_PACKET_TTL;
const int extern FEEDBACK_PACKET_IPPROTO; // should be some unused protocol
/**********************feedback variables************************/


static inline int skb_size(struct sk_buff *skb)
{
    return ETH_HLEN + skb->len;
}


static int inline skb_is_feedback(struct iphdr *iph)
{
    if(unlikely(iph->protocol != FEEDBACK_PACKET_IPPROTO))
        return 0;
    return iph->id;
}

/************************************Feedback***********************************************/

#endif /* evilbit.h */
