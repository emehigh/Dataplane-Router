#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAC_LEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *arp_table;
int arp_table_len;

char buf[MAX_PACKET_LEN];
int interface;




void send_icmp(int type) {
	
	char *packet = malloc(MAX_PACKET_LEN);
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	uint8_t *aux_mac = malloc(MAC_LEN);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// interschimb mac
	memcpy(aux_mac, eth_hdr->ether_dhost, MAC_LEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
	memcpy(eth_hdr->ether_shost, aux_mac, MAC_LEN);

	//interschimb ip
	uint32_t aux_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux_ip;


	// reset ttl si update checksum
	ip_hdr->tot_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	ip_hdr->ttl = 64;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	ip_hdr->protocol = 1;

	// icmp error/echo
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));


	//packet -> ether_header, ip_hdr si icmphdr
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	// trimit pachetul inapoi
	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

struct route_table_entry *get_best_route(uint32_t  dest_ip) 
{
    int idx = -1;	

    for (int i = 0; i < rtable_len; i++) 
	{
        if (ntohl(dest_ip & rtable[i].mask) == ntohl(rtable[i].prefix)) 
		{
			if (idx == -1) 
				idx = i;
			else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) 
				idx = i;
		}
    }
    if (idx != -1)
        return &rtable[idx];
	else
        return NULL;
}


int main(int argc, char *argv[])
{


	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 64275);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_entry) * 10);
	DIE(arp_table == NULL, "memory");
	arp_table_len = 0;
	uint8_t *mac = malloc(MAC_LEN);

	rtable_len = read_rtable(argv[1],rtable);
	queue q = queue_create();
	// arp_table_len = parse_arp_table("arp_table.txt",arp_table);
	while (1) {

		size_t len = 0;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		// verific daca pachetul e ipv4
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			printf("IPv4 packet received.\n");
				
				struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
				
				uint16_t temp = ip_hdr->check;
				ip_hdr->check = 0;
				if(temp != ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))){
					printf("Wrong checksum. Dropping packet...\n");
					continue;
				}
				if(ip_hdr->ttl <= 1){
					printf("Time exceeded. Dropping packet...");
					// daca ttl <= 1 trimit icmp error 
					send_icmp(11);
					continue;
				}
				else{
					printf("Packet ok. Updating ttl...\n");
					uint16_t old_ttl = ip_hdr->ttl;
					ip_hdr->ttl--;
					ip_hdr->check = ~(~temp +  ~(old_ttl) + (uint16_t)ip_hdr->ttl) - 1;
				}

				if(ip_hdr->daddr == inet_addr(get_interface_ip(interface))){
					printf("packet for router\n");
					send_icmp(0);
					continue;
				}
				//caut calea cea mai buna spre destinatie
				struct route_table_entry *rtableentry = get_best_route(ip_hdr->daddr);
				if(rtableentry == NULL){
					printf("Host unreachable\n");
					send_icmp(3);
					continue;
				}
				else {
				
					int arp_found = 0;
					int index = 0;
					for( index = 0; index < arp_table_len; index++){
						if(arp_table[index].ip == rtableentry->next_hop){
							arp_found = 1;
							break;
						}
						
					}
					// daca am o adresa mac mapata pentru next_hop trimit pachetul acolo
					if(arp_found){
						printf("Arp adress found.\n");
						get_interface_mac(rtableentry->interface, mac);
						memcpy(eth_hdr->ether_shost, mac,MAC_LEN);
						memcpy(eth_hdr->ether_dhost, arp_table[index].mac,MAC_LEN);
						send_to_link(rtableentry->interface,(char*)buf,len);
					}
					else{
						//daca nu, creez un pachet arp cu arp_request si fac broadcast cu el
						// si pachetul trimit il pun intr-un q de unde o sa trimit pachetele cand o sa am adresele mac de care am nevoie
						printf("Arp adress not found. Sending arp request...\n");
						struct ether_header *packet = malloc(len);
						memcpy(packet, eth_hdr, len);
						queue_enq(q,packet);

						memset(eth_hdr->ether_dhost, 0xff, MAC_LEN);
						get_interface_mac(rtableentry->interface, mac);

						memcpy(eth_hdr->ether_shost, mac, MAC_LEN);
	
						eth_hdr->ether_type = htons(ETHERTYPE_ARP);
						
						struct arp_header *arphdr_temp = (struct arp_header*)malloc(sizeof(struct arp_header));
						arphdr_temp->op = htons(ARP_REQUEST);
						arphdr_temp->spa = inet_addr(get_interface_ip(rtableentry->interface));
						arphdr_temp->tpa = rtableentry->next_hop;
						arphdr_temp->htype = htons(1);
						arphdr_temp->ptype = htons(2048);
						arphdr_temp->hlen = 6;
						arphdr_temp->plen = 4;
						memset(arphdr_temp->tha,0xff,6);
						get_interface_mac(rtableentry->interface,arphdr_temp->sha);
						
						char buf_to_send[MAX_PACKET_LEN];
						// char *buf_to_send = malloc(sizeof( struct ether_header ) + sizeof(struct arp_header));
						memcpy(buf_to_send, eth_hdr, sizeof(struct ether_header));
						memcpy(buf_to_send + sizeof(struct ether_header), arphdr_temp, sizeof(struct arp_header));
						send_to_link(rtableentry->interface,buf_to_send, sizeof(struct ether_header)+ sizeof(struct arp_header));
					}
				
				}
			
				
				
		}
		else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
			printf("Arp packet received.\n");
				//daca am primit packet arp cu request trimit inapoi adresa mea mac
				struct arp_header *arphdr = (struct arp_header *)(buf + sizeof(struct ether_header));
				
				if(ntohs(arphdr->op) == ARP_REQUEST && arphdr->tpa == inet_addr(get_interface_ip(interface))){
					
						printf("Packet from interface: %d\n",interface);
						printf("Arp request\n");

						get_interface_mac(interface,mac);
						memcpy(arphdr->tha, arphdr->sha, MAC_LEN);
						memcpy(arphdr->sha, mac, MAC_LEN);
						arphdr->op = htons(ARP_REPLY);

						uint32_t aux_ip = arphdr->spa;
						arphdr->spa = arphdr->tpa;
						arphdr->tpa = aux_ip;
						
						memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,MAC_LEN);
						memcpy(eth_hdr->ether_shost, mac,MAC_LEN);
						printf("Sending back mac adress...\n");
						char *arp_buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
						memcpy(arp_buf, eth_hdr, sizeof(struct ether_header));
						memcpy(arp_buf + sizeof(struct ether_header), arphdr, sizeof(struct arp_header));
						send_to_link(interface, arp_buf ,sizeof(struct ether_header) + sizeof(struct arp_header));
					
					
					
				}
				else if(ntohs(arphdr->op) == ARP_REPLY && arphdr->tpa == inet_addr(get_interface_ip(interface))){
					// daca am primit packet arp cu reply, mapez adresa ip la adresa mac primta in arp_table
					printf("Packet from interface %d\n", interface);
					printf("Arp reply\n");
					struct arp_entry arpentry;
					arpentry.ip = arphdr->spa;
					memcpy(arpentry.mac, arphdr->sha, MAC_LEN);
					
					arp_table[arp_table_len] = arpentry;
					arp_table_len++;
					// caut in q daca vreunul dintre pachetele mele poate folosi noua adresa mac primita
					// daca da, il trimit unde trebuia sa ajunga
					while(!queue_empty(q)){
						void *point = queue_deq(q);
						struct ether_header *ethhdr = (struct ether_header*)point;
						struct iphdr *pack = (struct iphdr*)(point + sizeof(struct ether_header));
						 struct route_table_entry *rtableentry = get_best_route(pack->daddr);
					
						if(rtableentry != NULL){
							int index = 0;
							int arp_found = 0;
							for(int i = 0; i < arp_table_len; i++){
								if(rtableentry->next_hop == arp_table[i].ip){
									index = i;
									arp_found = 1;
									break;
								}
							}
							if (arp_found) {
								memcpy(ethhdr->ether_dhost, arp_table[index].mac, MAC_LEN);							
								get_interface_mac(rtableentry->interface, ethhdr->ether_shost);
								send_to_link(rtableentry->interface,(char*)point,len);
								free(point);
								continue;
							}
						}
						

						break;
					}

				}
				
				
			

		}
		/* Note that packets received are in network order,

		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

