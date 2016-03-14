#include "ad.h"

pcap_t *dev;

void sniff (int opt){
    int r;
    char errbuf[PCAP_ERRBUF_SIZE];
    //dev_open = pcap_lookupdev(errbuf);
    struct bpf_program fl;
    bpf_u_int32 msk,net;
    const char filter_opt[]="";
    if (opt==1){
        dev=pcap_open_live("wlan0",FRAME_SIZE,0,-1,errbuf);
        if(dev==NULL){
           puts(errbuf);
           return;
        }
        r=pcap_lookupnet("wlan0",&net,&msk,errbuf);
        if(r==-1){
         puts(errbuf);
         return;
        }
    }
    if (opt==2){
        dev=pcap_open_live("eth0",FRAME_SIZE,0,-1,errbuf);
        if(dev==NULL){
           puts(errbuf);
           return;
        }
        r=pcap_lookupnet("eth0",&net,&msk,errbuf);
        if(r==-1){
         puts(errbuf);
         return;
        }
    }
    r=pcap_compile(dev,&fl,filter_opt,0,net);
    if (r==-1){
        puts("pcap_compile err\n");
        return;
    }

    pcap_loop(dev,-1,capturing,NULL);
}


void capturing(u_char *arg, const struct pcap_pkthdr* hdr, const u_char* packet){
    int i;
    struct sniff_eth *eth;
    struct sniff_arp *arp;
    struct sniff_ip *ip;
    struct sniff_udp *udp;
    struct sniff_tcp *tcp;
    eth=(struct sniff_eth*)packet;

    printf("ETHERNET HEADER\nsrc mac: ");
    for(i=0;i<5;i++){
            printf("%x-",eth->eth_smac[i]);
    }
    printf("%x",eth->eth_smac[5]);
    printf("\ndst mac: ");
    for(i=0;i<5;i++){
            printf("%x-",eth->eth_dmac[i]);
    }
    printf("%x",eth->eth_dmac[5]);
    printf("\ntype %x\n",ntohs(eth->eth_type));
    if (ntohs(eth->eth_type)==0x0806){
        printf("ARP HEADER\n");
        arp=(struct sniff_arp*)(packet+(sizeof(struct sniff_eth)));
        printf("operation:%x%x\n",arp->oper[0],arp->oper[1]);
    }
     if(ntohs(eth->eth_type)==0x0800){
         ip=(struct sniff_ip*)(packet+(sizeof(struct sniff_eth)));
         printf("IP HEADER\n");
         printf("source ip:");
         for (i=0;i<=2;i++){
             printf("%d.",ip->ip_source[i]);
         }
         printf("%d\n",ip->ip_source[3]);
         printf("dst ip:");
         for (i=0;i<=2;i++){
             printf("%d.",ip->ip_dest[i]);
         }
         printf("%d\n",ip->ip_dest[3]);
     }

     if(ip->protocol==1){
         printf("It's ICMP FRAME");
     }

     if(ip->protocol==6){
         printf("TCP HEADER\n");
         tcp=(struct sniff_tcp*)(packet+sizeof(struct sniff_eth)+sizeof(struct sniff_ip));
         printf("source port:%d\n",ntohs(*((int*)tcp->source_port)));
         printf("dst port:%d\n",ntohs(*((int*)tcp->dest_port)));
     }

     if(ip->protocol==17){
         printf("UDP HEADER\n");
         udp = (struct sniff_udp*)(packet+sizeof(struct sniff_eth)+sizeof(struct sniff_ip));
         printf("source port:%d\n",ntohs(*((int*)udp->source_port)));
         printf("dst port:%d\n",ntohs(*((int*)udp->dest_port)));

     }
}

