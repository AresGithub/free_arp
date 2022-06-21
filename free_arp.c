#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <net/if.h>        //for struct ifreq
#include <math.h>

/*
https://www.bbsmax.com/A/QV5ZQvQ7Jy/
https://blog.csdn.net/weixin_40639467/article/details/109367840
*/

const char ip_mask_list[33][64] = {
    "0.0.0.0",
    "128.0.0.0",
    "192.0.0.0",
    "224.0.0.0",
    "240.0.0.0",
    "248.0.0.0",
    "252.0.0.0",
    "254.0.0.0",
    "255.0.0.0",
    "255.128.0.0",
    "255.192.0.0",
    "255.224.0.0",
    "255.240.0.0",
    "255.248.0.0",
    "255.252.0.0",
    "255.254.0.0",
    "255.255.0.0",
    "255.255.128.0",
    "255.255.192.0",
    "255.255.224.0",
    "255.255.240.0",
    "255.255.248.0",
    "255.255.252.0",
    "255.255.254.0",
    "255.255.255.0",
    "255.255.255.128",
    "255.255.255.192",
    "255.255.255.224",
    "255.255.255.240",
    "255.255.255.248",
    "255.255.255.252",
    "255.255.255.254",
    "255.255.255.255",
};

#define print_errno(fmt, ...) \
    printf("[%d] errno=%d (%s) #" fmt, \
        __LINE__, errno, strerror(errno), ####__VA_ARGS__)
 
int myPow1(int x, int n)
{
    int result = 1;
    int i = 0;

    if (n == 0) 
        return result;

    for (i = 0; i < n; i++)
        result *= x;

    return result;
}

// 返回值是实际写入char * mac的字符个数 (不包括'\0')
int get_mac(char *ifname, unsigned char mac[])    
{
    struct ifreq ifreq;
    int sock;

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
        perror ("socket");
        return -1;
    }

    strcpy (ifreq.ifr_name, ifname);    //Currently, only get eth0

    if (ioctl (sock, SIOCGIFHWADDR, &ifreq) < 0) {
        perror ("ioctl");
        return -1;
    }

    memcpy(mac, (unsigned char *) ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

    return ETH_ALEN;
}

static unsigned char s_ip_frame_data[ETH_DATA_LEN];
static unsigned int s_ip_frame_size = 0;
 
static int send_free_arp(const char *if_name, unsigned char smac[],char *src_addr,int mask)
{
    struct ether_header *eth = NULL;
    struct ether_arp *arp = NULL;
    struct ifreq ifr;
    struct in_addr daddr;
    struct in_addr saddr;
    struct sockaddr_ll sll;
    int skfd;
    int n = 0;
    unsigned char dmac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

    saddr.s_addr = inet_addr(src_addr);
    daddr.s_addr = saddr.s_addr; //  | htonl(myPow1(2,32-mask) - 1);
    
    memset(s_ip_frame_data, 0x00, sizeof(unsigned char)*ETH_DATA_LEN);

    skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (skfd < 0) {
        print_errno("socket() failed! \n");
            return -1;
    }

    bzero(&ifr,sizeof(ifr));
    strcpy(ifr.ifr_name, if_name);
    if (-1 == ioctl(skfd, SIOCGIFINDEX, &ifr)) {
        print_errno("ioctl() SIOCGIFINDEX failed!\n");
            return -1;
    }
    // printf("ifr_ifindex = %d\n", ifr.ifr_ifindex);

    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_family  = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);

    eth = (struct ether_header*)s_ip_frame_data;
    eth->ether_type = htons(ETHERTYPE_ARP);
    memcpy(eth->ether_dhost, dmac, ETH_ALEN);
    memcpy(eth->ether_shost, smac, ETH_ALEN);

    arp = (struct ether_arp*)(s_ip_frame_data + sizeof(struct ether_header));
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = 4;
    //arp->arp_op = htons(ARPOP_REQUEST);
    arp->arp_op = htons(ARPOP_REPLY);

    memcpy(arp->arp_sha, smac, ETH_ALEN);
    memcpy(arp->arp_spa, &saddr.s_addr, 4);
    memcpy(arp->arp_tha, dmac, ETH_ALEN);
    memcpy(arp->arp_tpa, &daddr.s_addr, 4);
    s_ip_frame_size = sizeof(struct ether_header) + sizeof(struct ether_arp);
    n = sendto(skfd, s_ip_frame_data, s_ip_frame_size, 0, \
            (struct sockaddr*)&sll, sizeof(sll));
    if (n < 0) {
        print_errno("sendto() failed!\n");
    }
    /*
    else {
        printf("sendto() n = %d \n", n);
    }
    */
    close(skfd);
    return 0;
}

// 判断网口连接状态
// if_name like "ath0", "eth0". Notice: call this function
// need root privilege.
// return value:
// -1 -- error , details can check errno
// 1 -- interface link up
// 0 -- interface link down.
int get_netlink_status(const char *if_name)
{
    int skfd;
    struct ifreq ifr;
    struct ethtool_value edata;
    edata.cmd = ETHTOOL_GLINK;
    edata.data = 0;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (char *) &edata;
    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 )) < 0)
        return -1;
    if(ioctl( skfd, SIOCETHTOOL, &ifr ) == -1)
    {
        close(skfd);
        return -1;
    }
    close(skfd);
    return edata.data;
}

int get_local_ip(char *dev, char *ip, char *mask)
{
    int fd, intrface, retn = 0;
    char *p = NULL;
    struct ifreq buf[INET_ADDRSTRLEN];  //这个结构定义在/usr/include/net/if.h，用来配置和获取ip地址，掩码，MTU等接口信息的
    struct ifconf ifc;
 
	/* 1 建立socket链接, 利用ioctl来自动扫描可用网卡 */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        ifc.ifc_len = sizeof(buf);
 
        // caddr_t,linux内核源码里定义的：typedef void *caddr_t；
        ifc.ifc_buf = (caddr_t)buf;
 
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {  /*2  这里获取到可用网卡清单，包括网卡ip地址，mac地址*/
            intrface = ifc.ifc_len/sizeof(struct ifreq);  //计算出有效网卡的数量//  
            while (intrface-- > 0)
            {
                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))) { /*3  遍历并索引指定网卡的地址*/
					if(strcmp(buf[intrface].ifr_ifrn.ifrn_name, dev) == 0) {
						p=(inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                        memcpy(ip, p, strlen(p));
						// printf("IP:%s\n", ip);
					}
                }

                if (!(ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface]))) { /*3  遍历并索引指定网卡的地址*/
					if(strcmp(buf[intrface].ifr_ifrn.ifrn_name, dev) == 0) {
						p=(inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                        memcpy(mask, p, strlen(p));
						// printf("MASK:%s\n", mask);
					}
                }
 
 
            }
        }
 
        close(fd);
 
        return 0;
    }

    return -1;
}

int get_netmask_len(char* mask)
{
    int i = 0;
    for (i = 0; i < 33; i++) {
        if (strcmp(mask, ip_mask_list[i]) == 0) {
            return i;
        }
    }
    return -1;
}

int main(int argc,char *argv[])
{
    char ip[64];
    char mask[64];
    unsigned char mac[ETH_ALEN] = { 0x00 };
    int link_status = 0;
    int t = 0;
    int need_send_arp = 0;
    char if_name[64] = { "eth0" };
    int send_arp = 0;
    char old_ip[64] = { 0 };
    int mask_len = 0;

    while (1) {
        need_send_arp = 0;

        t = get_netlink_status(if_name);
        if (t != link_status) {
            printf("%s link status change to %s. \r\n", if_name, t==0?"unlink":"link");
            link_status = t;
            if (link_status==1) 
                need_send_arp = 1;
        }
        
        memset(ip, 0, 64);
        memset(mask, 0, sizeof(mask));
        if (get_local_ip(if_name, ip, mask) == 0) {
            if (strcmp(old_ip, ip) != 0) {
                printf("%s ip changed. \r\n", if_name);
                memcpy(old_ip, ip, 64);
                need_send_arp = 1;
            }
        } else {
            printf("get %s ip address failed. \r\n", if_name);
        }

        if (need_send_arp == 1) {
            send_arp = 1;
            // 变为link up 发送一次arp reply包
            if (get_mac(if_name, mac) < 0) {
                printf("get %s mac address failed. \r\n", if_name);
                send_arp = 0;
            } 

            memset(ip, 0, sizeof(ip));
            memset(mask, 0, sizeof(mask));
            if (get_local_ip(if_name, ip, mask) < 0) {
                printf("get %s ip address failed. \r\n", if_name);
                send_arp = 0;
            } else {
                mask_len = get_netmask_len(mask);
                if (mask_len < 0) {
                    printf("invaid mask %s. \r\n", mask);
                }
            }

            if (send_arp) {
                printf("%s - %02X:%02X:%02X:%02X:%02X:%02X - %s %s (%d) \r\n", if_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip, mask, mask_len);
                usleep(300*1000);
                send_free_arp(if_name, mac, ip, mask_len);
            }
        }

        sleep(1);
    }
}