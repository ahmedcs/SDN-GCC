#ifndef RWNDQ_H
#define RWNDQ_H 1

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

//#include "myflow.h"

/******************************************Ahmed***********************************************/
#define DEV_MAX 200
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))





void add_connection(struct net_device * dev);
void del_connection(struct net_device * dev);
void reset_connections(int i);
enum hrtimer_restart timer_callback(struct hrtimer *timer);
void rwndq_process(struct sk_buff *skb,  struct vport *inp , struct vport *outp, struct sw_flow_key *key);
void update_dev(const struct net_device *dev, int i);
void del_dev(const struct net_device * dev, int i);
void add_dev(const struct net_device * dev);
void init_rwndq(void);
void cleanup_rwndq(void);
/******************************************Ahmed***********************************************/

#endif /* rwndq.h */
