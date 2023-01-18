#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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


#include "datapath.h"


static int M = 16;
module_param(M, int, 0644);
MODULE_PARM_DESC(M, " M determines number of intervals before updating the window");

static long int interval = 200L;
module_param(interval, long, 0644);
MODULE_PARM_DESC(interval, " interval determines the timer interval");

static spinlock_t globalLock;
static struct hrtimer my_hrtimer;
static ktime_t ktime;

static unsigned short devcount=0;
static bool timerrun=false;
static unsigned short count=0;
static unsigned int negcount[DEV_MAX];
static bool congested[DEV_MAX];
static short devindex[DEV_MAX];
static unsigned int wnd[DEV_MAX];
static unsigned int oldwnd[DEV_MAX];
static unsigned int qlimit[DEV_MAX];
static short conncount[DEV_MAX];
static short totalconn=0;
static short prevtotal=0;
static int incr[DEV_MAX];
static bool slowstart[DEV_MAX];
static bool incast[DEV_MAX];
static int syncount[DEV_MAX];
static unsigned short MSS[DEV_MAX];
static bool fail=false;
static unsigned int max_ackno=0;
static bool dropornot=false;

void add_connection(struct net_device * dev)
{
    int i=0;
    while(i < devcount)
    {
        if(devindex[i] == dev->ifindex)
            break;
        i++;
    }
    if(i==devcount)
    {
        add_dev(dev);
        conncount[i]++;
    }
    else
    {
        update_dev(dev, i);
        conncount[i]++;
    }
    if(conncount[i]>1)
    {
        wnd[i] = wnd[i] * (conncount[i]-1) / conncount[i];
        if(wnd[i]<MSS[i])//TCP_MSS_DEFAULT)
            wnd[i]=MSS[i];//TCP_MSS_DEFAULT;
    }
    if(!timerrun)
     {
            if (hrtimer_active(&my_hrtimer) != 0)
                  hrtimer_cancel(&my_hrtimer);
            ktime = ktime_set(0 , interval * ( (unsigned long) 1E3L) );
            hrtimer_start(&my_hrtimer, ktime, HRTIMER_MODE_REL);
            timerrun=true;

      }
}

void del_connection(struct net_device * dev)
{
    int i=0;
    while(i < devcount)
    {
        if(devindex[i] == dev->ifindex)
            break;
        i++;
    }
    if(i<devcount)
    {
        if(conncount[i]>0)
	   conncount[i]--;
        /*if(conncount[i]==0) 
	 //reset_connections(i); 
        else*/
        if(conncount[i]>0){
            wnd[i]= wnd[i] * (conncount[i]+1) / conncount[i];
            if(wnd[i]>65535)
                wnd[i]=65535;
        }

    }

}

void reset_connections(int i)
{
    if(i!=-1)
    {
        wnd[i] = (qlimit[i] >> 3);
        incr[i] = 0;
        slowstart[i]=true;
        negcount[i]=0;
        //congested[i]=false;
    }
    else
    {
        i=0;
        while ( i<devcount)
        {
            wnd[i] = (qlimit[i] >> 3);
            incr[i] = 0;
            slowstart[i]=true;
            negcount[i]=0;
            //congested[i]=false;
            i++;
        }
        count=0;
    }
}

enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
    //timerrun=false;
    struct net_device * dev;
    int i=0;
    while (i<devcount)
    {
        if(conncount[i]>0)
        {
            //timerrun=true;
            dev = dev_get_by_index(&init_net, devindex[i]);
            int backlog=dev->qdisc->qstats.backlog;
            if(!slowstart[i])
            {
                incr[i] += (qlimit[i] >> 3) - backlog;
                if (count == M)
                {
                    if(negcount[i] == M )
                    {
                        wnd[i]=MSS[i];
                        slowstart[i]=true;
                    }
                    else
                        wnd[i] += incr[i]/(M*conncount[i]);
                    incr[i] = 0;
                    negcount[i]=0;
                }

            }
            else
                wnd[i]+= (MSS[i]<<1) * interval/(100 * M);

            if(wnd[i]> 65535)
                wnd[i]=65535;
            else if(wnd[i] < MSS[i])//TCP_MSS_DEFAULT)
                wnd[i] = MSS[i];//TCP_MSS_DEFAULT;
            if(slowstart[i])
            {
                if((qlimit[i] >> 2)  < backlog)
                    slowstart[i]=false;
	    }
            else
	    {
		    if (qlimit[i]-(qlimit[i] >> 4 )  < backlog)
                   	 negcount[i]++;
            }

        }
        i++;

    }
    if(count == M)
    {
        count=0;
        /*if(!timerrun)
            goto stop;*/
    }
    else
        count++;

    if(rwndq_enabled())
    {
	timerrun=true;
        ktime_t ktnow = hrtimer_cb_get_time(&my_hrtimer);
        int overrun = hrtimer_forward(&my_hrtimer, ktnow, ktime);
        return HRTIMER_RESTART;
    }
stop:
    timerrun=false;
    //reset_connections(-1);
    return HRTIMER_NORESTART;
}

void rwndq_process(struct sk_buff *skb,  struct vport *inp , struct vport *outp, struct sw_flow_key *key)
{
    const struct net_device *in=netdev_vport_priv(inp)->dev;
    const struct net_device *out=netdev_vport_priv(outp)->dev;
    if (skb && in && out && !fail)
    {

        struct iphdr * ip_header = (struct iphdr *)skb_network_header(skb);
        if (ip_header && ip_header->protocol == IPPROTO_TCP)
        {

            struct tcphdr * tcp_header = (void *)(skb_network_header(skb) + ip_header->ihl * 4);
            if(tcp_header->ack)
            {
                int i=0;
                while(i < devcount)
                {
                    if(devindex[i] == in->ifindex)
                        break;
                    i++;
                }
                if (i<devcount && conncount[i] && wnd[i] < ntohs(tcp_header->window))
                {
                    __be16 old_win = tcp_header->window;
                    __be16 new_win = htons(wnd[i]);
                    tcp_header->window = new_win;
                    csum_replace2(&tcp_header->check, old_win, new_win);
                                    }
            }


        }
    }
}

void add_dev(const struct net_device * dev)
{
    if(dev==NULL || devcount+1>DEV_MAX)
    {
        fail=true;
        timerrun=false;
        printk(KERN_INFO "OpenVswitch : Fatal Error Exceed Allowed number of Devices : %d \n", devcount);
        return;
    }
    if(dev->qdisc->limit <=0 || psched_mtu(dev) <=0)
        return;
    devindex[devcount] = dev->ifindex;
    MSS[devcount] = (psched_mtu(dev) - 54);
    qlimit[devcount] = dev->qdisc->limit;
    wnd[devcount] = qlimit[devcount] >> 3;
    conncount[devcount] = 0;
    incr[devcount] = 0;
    slowstart[devcount]=true;
    negcount[devcount]=0;
    //congested[devcount]=false;

    printk(KERN_INFO "OpenVswitch ADD: [%i:%s] initials : %d %d %d %d %d\n", devindex[devcount], (const char*)dev->name ,  qlimit[devcount], dev->tx_queue_len, psched_mtu(dev), wnd[devcount], MSS[devcount] );
    devcount++;
    printk(KERN_INFO "OpenVswitch ADD: total number of detected devices : %d \n", devcount);

}

void update_dev(const struct net_device * dev, int i)
{
    if(qlimit[i] == dev->qdisc->limit && MSS[i] == (psched_mtu(dev) - 54))
        return;

    MSS[i] = (psched_mtu(dev) - 54);
    qlimit[i] = dev->qdisc->limit;

    printk(KERN_INFO "OpenVswitch update: [%i:%s] initials : %d %d %d %d %d\n", devindex[i], (const char*)dev->name ,  qlimit[i], dev->tx_queue_len, psched_mtu(dev), wnd[i], MSS[i] );
    return;

}

void del_dev(const struct net_device * dev, int i)
{
    if(dev==NULL || devcount<=0)
        return;
    if(i<0)
    {
        int i=0;
        while(i<devcount && devindex[i]!=dev->ifindex)
        {
            i++;
        }
    }
    if(i<devcount)
    {
        printk(KERN_INFO "OpenVswitch DEL: [%d:%s] \n", devindex[i], (const char*)dev->name);
        int j=i;
        while(j<devcount && devindex[j+1]!=-1)
        {
            devindex[j] = devindex[j+1];
            MSS[j] = MSS[j+1];
            wnd[j] = wnd[j+1];
            qlimit[j] = qlimit[j+1];
            conncount[j] = conncount[j+1];
            incr[j] = incr[j+1];
            slowstart[j]=slowstart[j+1];
            negcount[j]=negcount[j+1];
            //congested[j]=congested[j+1];

            j++;
        }

        devcount--;
        printk(KERN_INFO "OpenVswitch DEL: total number of detected devices : %d \n", devcount);
    }
}


void init_rwndq(void)
{

    hrtimer_init(&my_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    my_hrtimer.function = &timer_callback;
    timerrun=false;

    devcount=0;
    fail=false;

    int i=0;
    while( i < 10)
    {

        devindex[i]=-1;
        conncount[i]=0;
        MSS[i]=0;
        wnd[i]=0;
        qlimit[i]=0;
        incr[i]=0;
        slowstart[i]=false;
        negcount[i]=0;
        //congested[i]=false;
        i++;

    }
    if(interval<0)
        interval = 1000L;
    if(M<0)
        M=8;
    printk(KERN_INFO "OpenVswitch Init: interval : %ld , M : %d, rwndq_enable: %d \n", interval, M, rwndq_enabled());

    return;
}

void cleanup_rwndq(void)
{
    int ret_cancel = 0;
    while( hrtimer_callback_running(&my_hrtimer) )
    {
        ret_cancel++;
    }
    if (ret_cancel != 0)
    {
        printk(KERN_INFO " OpenVswitch: testjiffy Waited for hrtimer callback to finish (%d)\n", ret_cancel);
    }
    if (hrtimer_active(&my_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&my_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy active hrtimer cancelled: %d \n", ret_cancel);
    }
    if (hrtimer_is_queued(&my_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&my_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy queued hrtimer cancelled: %d \n", ret_cancel);
    }
    printk(KERN_INFO "OpenVswitch: Stop RWNDQ \n");


}

