#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <arpa/inet.h>

#include <time.h>
#include <sys/time.h>
#include <sys/sysinfo.h>

#define TABLE_SIZE 1000001

struct packet_info {
	u_int32_t id;
	int is_harmful;
};

typedef struct site_node {
	char *host;
	struct site_node *next;
} site_node;

site_node *hash_table[TABLE_SIZE] = {NULL};
int total = 0;

void get_memory_usage() {

	struct sysinfo info;
	sysinfo(&info);

	printf("Process cnt: %d\n", info.procs);
	printf("Total Memory: %ld\n", info.totalram);
	printf("Free Memory: %ld\n", info.freeram);
	printf("Used Memory: %ld\n", info.totalram - info.freeram);
	printf("Swap Memory: %ld\n", info.totalswap);
	printf("Used Buffer: %ld\n", info.bufferram);

	return;
}

unsigned int djb2(const char* str) {
	unsigned long hash = 5381;
	int c;
	while (c == *str++) {
		hash = (((hash << 5) + hash) + c) % TABLE_SIZE;
	}
	return hash % TABLE_SIZE;
}

void hash_append(const char* host) {
	if (!host || strlen(host) == 0) {
		return;
	}

	unsigned int idx = djb2(host);
	site_node *new_node = (site_node *)malloc(sizeof(site_node));
	if (!new_node) {
		fprintf(stderr, "Memory allocation failed for new node\n");
		exit(1);
	}

	new_node -> host = strdup(host);
	if (!new_node -> host) {
		fprintf(stderr, "Failed to copy host name");
		exit(1);
	}

	new_node -> next = hash_table[idx];
	hash_table[idx] = new_node;
}

void add_harmful_host(const char* fn) {
	FILE *file = fopen(fn, "r");
	if (!file) {
		fprintf(stderr, "Cannot open file\n");
		exit(1);
	}

	char line[100];
	char host[100];

	printf("Before loading 1m-block\n\n");
	get_memory_usage();
	struct timespec start, end;
	double diff;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while(fgets(line, sizeof(line), file) != NULL) {
		char *ptr = strchr(line, ',');
		strcpy(host, ptr + 1);
		int len = strlen(host);
		if (len > 0 && host[len - 1] == '\n') {
			host[--len] = '\0';
		}

		if (len > 0) {
			hash_append(host);
			total++;
		}
	}

	printf("After loading 1m-block\n\n");
	get_memory_usage();

	clock_gettime(CLOCK_MONOTONIC, &end);
	diff = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
	printf("\nIt took %.2lf milliseconds to load %d harmful sites\n\n", diff, total);

}

int is_harmful(const char* host) {
	struct timespec start, end;
	double diff;
	clock_gettime(CLOCK_MONOTONIC, &start);

	unsigned int idx = djb2(host);

	site_node *current = hash_table[idx];

	while(current){
		if (strlen(current->host) == strlen(host) && strcmp(current->host, host) == 0) {
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
			printf("It took %.2lf milliseconds to search harmful sites\n", diff);
			return 1;
		}
		current = current -> next;
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	diff = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
	printf("It took %.2lf milliseconds to search harmful sites\n", diff);
	return 0;
}

static struct packet_info print_pkt(struct nfq_data *tb)
{
	struct packet_info result = {0, 0};
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		result.id = id;
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	// check IP, TCP, HTTP
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);

		// get IP header
		struct iphdr *iph = (struct iphdr *)data;

		if (ret >= sizeof(struct iphdr)) {
			char src_ip[INET_ADDRSTRLEN];
			char dst_ip[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);

			printf("IP: Version=%u IHL=%u TOS=%u Total Length=%u ID=%u\n", iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len), ntohs(iph->id));
			printf("IP: TTL=%u Protocol=%u Checksum=%u\n", iph->ttl, iph->protocol, ntohs(iph->check));
			printf("IP: Source=%s Destination=%s\n", src_ip, dst_ip);

			// check TCP	
			if (iph->protocol == 6) {
				int ip_header_len = iph->ihl * 4;

				if (ret >= ip_header_len + sizeof(struct tcphdr)) {
					// get TCP header
					struct tcphdr *tcph = (struct tcphdr *)(data + ip_header_len);

					// print TCP header
					printf("TCP: Source Port=%u Destination Port=%u\n", ntohs(tcph->source), ntohs(tcph->dest));
					printf("TCP: Sequence=%u Ack=%u\n", ntohl(tcph->seq), ntohl(tcph->ack_seq));
					printf("TCP: Data Offset=%u Flags=%c%c%c%c%c%c\n",
							tcph->doff,
							(tcph->urg ? 'U' : '-'),
							(tcph->ack ? 'A' : '-'),
							(tcph->psh ? 'P' : '-'),
							(tcph->rst ? 'R' : '-'),
							(tcph->syn ? 'S' : '-'),
							(tcph->fin ? 'F' : '-'));

					int tcp_header_len = tcph->doff * 4;
					int payload_offset = ip_header_len + tcp_header_len;

					// check HTTP
					if (ret > payload_offset + 10) {
						// get HTTP payload
						unsigned char *http_data = data + payload_offset;
						int http_data_len = ret - payload_offset;

						if (http_data_len > 4 &&
								(memcmp(http_data, "GET ", 4) == 0 ||
								 memcmp(http_data, "POST ", 5) == 0 ||
								 memcmp(http_data, "HEAD ", 5) == 0 ||
								 memcmp(http_data, "PUT ", 4) == 0 ||
								 memcmp(http_data, "DELETE ", 7) == 0)) {

							printf("HTTP: Detected HTTP request\n");

							char *http_copy = (char *)malloc(http_data_len + 1);
							if (http_copy) {
								memcpy(http_copy, http_data, http_data_len);
								http_copy[http_data_len] = '\0';

								// find Request
								char *end_of_req_line = strstr(http_copy, "\r\n");
								if (end_of_req_line) {
									*end_of_req_line = '\0';
									printf("HTTP: Request Line: %s\n", http_copy);
									*end_of_req_line = '\r';
								}

								// find Host header
								char *host_header = strstr(http_copy, "Host: ");
								if (host_header) {
									host_header += 6;
									char *end_of_host = strstr(host_header, "\r\n");
									if (end_of_host) {
										*end_of_host = '\0';
										printf("HTTP: Host: %s\n", host_header);

										// check harmful host
										if (is_harmful(host_header)) {
											printf("*** Harmful host detected: %s ***\n", host_header);
											result.is_harmful = 1;
										}

										*end_of_host = '\r';
									}
								}

								free(http_copy);
							}
						}
					}
				}
			}
		}
	}

	fputc('\n', stdout);

	return result;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct packet_info pkt_info = print_pkt(nfa);
	printf("entering callback\n");

	if (pkt_info.is_harmful) {
		printf("Dropping packet for harmful host\n");
		return nfq_set_verdict(qh, pkt_info.id, NF_DROP, 0, NULL);
	} 
	else {
		return nfq_set_verdict(qh, pkt_info.id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv) {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		fprintf(stderr, "syntax : 1m-block <site list file>\n");
		fprintf(stderr, "sample : 1m-block top-1m.csv\n");
		exit(1);
	}

	add_harmful_host(argv[1]);
	if (total == 0) {
		fprintf(stderr, "No Harmful host loaded\n");
		exit(1);
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	printf("Running... (Press Ctrl+C to stop)\n");

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
