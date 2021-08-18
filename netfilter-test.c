#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnet.h> //hdr
#include <string.h> //strnstr

#include <libnetfilter_queue/libnetfilter_queue.h>

char* hostName; //hostName
int block = 0; //NF_DROP

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

char* strnstr(const char *big, const char *little, size_t len)
{
	//strnstr 함수 출처 https://minsoftk.tistory.com/33
	size_t i;
	size_t temp;
	i = 0;

	while (big[i] && i < len)
	{
		temp = 0;
		if (little[temp] == big[i + temp])
		{
			while (little[temp] && big[i + temp])
			{
				if (little[temp] != big[i + temp] || (i + temp) >= len)
					break;
				temp++;
			}
			if (little[temp] == '\0')
				return (&((char *)big)[i]);
			}
			i++;
		}
		return ((void *)0);
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	struct libnet_ipv4_hdr* ip; //ipv4 hdr
	struct libnet_tcp_hdr* tcp; //tcp hdr
	unsigned char* http; //http

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
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

	// nfq_get_payload 이후 패킷의 시작 위치와 패킷의 길이를 알아내고 나서 IP, TCP, HTTP 형식으로 parsing을 한다.
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
      printf("payload_len=%d\n ", ret);
      //dump(data, ret);

			//ip hdr, tcp hdr 받음
			ip = (struct libnet_ipv4_hdr*)(data);
    	tcp = (struct libnet_tcp_hdr*)(data + (ip->ip_hl * 4)); //ip_hl * 4 == 20
			if((ip->ip_p) == IPPROTO_TCP) //상위레벨 프로토콜이 TCP == 6(IPPROTO_TCP), UDP == 17(IPPROTO_UDP)
			{
				if(ntohs(tcp->th_dport) == 80) //Destination port == 80 http 헤더
				{
					http = (unsigned char*)(data + (ip->ip_hl * 4) + (tcp->th_off * 4)); //th_off * 4 == 20 or 32
					//printf("http : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n", http);
					//printf("hostName : %s @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n", hostName);
					//strstr 안쓰고 비교 하는법? >> strnstr

					if(strnstr(http, hostName, strlen(http)) != NULL) //strnstr 포인터
					{
						//printf("test.gilgil.net@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
						block = 1; //block == 1, NF_DROP
					}
					else
					{
						block = 0; //block == 0, NF_ACCEPT
					}
				}
			}

  }

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	return block == 1 ? nfq_set_verdict(qh, id, NF_DROP, 0, NULL) : nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2) //인자 1개만 받아야 함.
	{
		fprintf(stderr, "error argument\n");
		exit(1);
	}

	hostName = argv[1]; //argv[1] hostName에 복사

	//시스템 함수 사용법 - http://www.digipine.com/index.php?mid=clan&document_srl=574
	int iptableF = system("sudo iptables -F");
	int iptableOut = system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	int iptableIn = system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");

	if(iptableF == 127 || iptableF == -1)
	{
		printf("%d\n", iptableF);
		fprintf(stderr, "error sudo iptables -F\n");
		exit(1);
	}

	if(iptableOut == 127 || iptableOut == -1)
	{
		fprintf(stderr, "error sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0\n");
		exit(1);
	}

	if(iptableIn == 127 || iptableIn == -1)
	{
		fprintf(stderr, "error sudo iptables -A INPUT -j NFQUEUE --queue-num 0\n");
		exit(1);
	}

	//set iptables by system function

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
