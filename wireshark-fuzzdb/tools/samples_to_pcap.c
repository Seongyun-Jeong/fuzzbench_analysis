/*
 * (C) Copyright 2017 Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <string.h>

static void
write_pcap(void)
{
	unsigned int t[6];

	t[0] = 0xa1b2c3d4; /* magic */
	t[1] = 0x00040002; /* version */
	t[2] = 0; /* thiszone */
	t[3] = 0; /* sigfigs */
	t[4] = 65535; /* snaplen */
	t[5] = 1;     /* eth */

	fwrite(t, 1, sizeof(t), stdout);
}

static void
write_ip_packet(unsigned char *pkt, size_t pkt_len)
{
	unsigned int t[4];

	t[0] = 42;
	t[1] = 42;
	t[2] = pkt_len + 14;
	t[3] = pkt_len + 14;

	fwrite(t, 1, sizeof(t), stdout);

	/* fake ethernet */
	{
		unsigned char addr[6];

		memset(addr, 0xaa, 6);
		fwrite(addr, 1, 6, stdout);
		fwrite(addr, 1, 6, stdout);
		fwrite("\x08\x00", 1, 2, stdout); /* IPv4 */
	}

	/* fake IPv4 address */
	{
		memset(&pkt[12], 0xaa, 4);
		memset(&pkt[16], 0xaa, 4);
	}

	fwrite(pkt, 1, pkt_len, stdout);
}

static void
write_eth_ip_common(int proto, size_t payload_len)
{
	unsigned int t[4];
	unsigned int len;

	len = 14 + 20 + payload_len;

	t[0] = 42;
	t[1] = 42;
	t[2] = len;
	t[3] = len;

	fwrite(t, 1, sizeof(t), stdout);
	/* fake ethernet */
	{
		unsigned char addr[6];

		memset(addr, 0xaa, 6);
		fwrite(addr, 1, 6, stdout);
		fwrite(addr, 1, 6, stdout);
		fwrite("\x08\x00", 1, 2, stdout); /* IPv4 */
	}

	/* fake IPv4 */
	{
		unsigned char ip[12] = "\x45\x00\x00\x40\x3d\x61\x40\x00\x40\x11\xff\x49";
		unsigned char ipaddr[4];

		memset(ipaddr, 0xaa, 4);

		ip[2] = (payload_len + 20) >> 8;
		ip[3] = (payload_len + 20) >> 0;
		ip[9] = proto;

		fwrite(ip, 1, 20 - 8, stdout);

		fwrite(ipaddr, 1, 4, stdout);
		fwrite(ipaddr, 1, 4, stdout);
	}

	fprintf(stderr, "wrote %u\n", len);
}

static void
write_udp_packet(unsigned char *udp, size_t udp_len)
{
	write_eth_ip_common(17 /* udp */, udp_len);

	udp[4] = udp_len >> 8;
	udp[5] = udp_len >> 0;

	/* crc */
	udp[6] = 0;
	udp[7] = 0;

	/* udp */
	fwrite(udp, 1, udp_len, stdout);
}

static void
write_sctp_packet(unsigned char *sctp, size_t sctp_len)
{
	write_eth_ip_common(132 /* sctp */, sctp_len);

	fwrite(sctp, 1, sctp_len, stdout);
}

static void
write_tcp_packet(unsigned char *tcp, size_t tcp_len)
{
	unsigned int t[4];
	unsigned int len;

	len = 14 + 20 + tcp_len;

	t[0] = 42;
	t[1] = 42;
	t[2] = len;
	t[3] = len;

	fwrite(t, 1, sizeof(t), stdout);

	/* fake ethernet */
	{
		unsigned char addr[6];

		memset(addr, 0xaa, 6);
		fwrite(addr, 1, 6, stdout);
		fwrite(addr, 1, 6, stdout);
		fwrite("\x08\x00", 1, 2, stdout); /* IPv4 */
	}

	/* fake IPv4 */
	{
		unsigned char ip[12] = "\x45\x00\x00\x40\x3d\x61\x40\x00\x40\x11\xff\x49";
		unsigned char ipaddr[4];

		memset(ipaddr, 0xaa, 4);

		ip[2] = 0;
		ip[2] = (20 + tcp_len) >> 8;
		ip[3] = (20 + tcp_len);
		ip[9]=  6;

		fwrite(ip, 1, 20 - 8, stdout);

		fwrite(ipaddr, 1, 4, stdout);
		fwrite(ipaddr, 1, 4, stdout);
	}

	fwrite(tcp, 1, tcp_len, stdout);
}

static void
write_tcp_packet_raw(unsigned char *tcp_payload, size_t payload_len, int port)
{
	static int seq_id = 0;

	char buf[20 + payload_len];

	memset(buf, 0, 20);

	buf[0] = port >> 8;
	buf[1] = port >> 0;
	buf[2] = port >> 8;
	buf[3] = port >> 0;

	/* seq # */
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = 0;
	buf[7] = seq_id;

	seq_id += payload_len;

	/* ack # */
	buf[8] = 0;
	buf[9] = 0;
	buf[10] = 0;
	buf[11] = 0;

	buf[12] = 5 << 4;

	memcpy(&buf[20], tcp_payload, payload_len);

	write_tcp_packet(buf, 20 + payload_len);
}


static void
write_udp_packet_raw(void *dns, size_t payload_len, int port)
{
	char buf[8 + payload_len];

	buf[2] = port >> 8;
	buf[3] = port >> 0;
	buf[0] = port >> 8;
	buf[1] = port >> 0;
	buf[4] = payload_len >> 8;
	buf[5] = payload_len >> 0;
	/* crc */
	buf[6] = 0;
	buf[7] = 0;
	memcpy(&buf[8], dns, payload_len);

	write_udp_packet(buf, 8 + payload_len);
}

static void
fuzz_tcp_port(unsigned char *tcp_hdr, unsigned short port_no)
{
	static int a = 1024;

	/* src port */
	tcp_hdr[0] = (a) >> 8;
	tcp_hdr[1] = a;
	a++;

	/* dst port */
	tcp_hdr[2] = port_no >> 8;
	tcp_hdr[3] = port_no;

	memset(tcp_hdr + 4, 0xAA, 4); /* seq */
	memset(tcp_hdr + 8, 0, 4);    /* ack */
	tcp_hdr[12] = 0x50; /* tcp hdr len */
	tcp_hdr[13] = 0x00; /* flags */
	memset(tcp_hdr + 14, 0xAA, 2); /* window size */
	memset(tcp_hdr + 16, 0, 4);
}

static unsigned int
get_ntohs(unsigned char *buf)
{
	return (buf[0] << 8) | buf[1];
}

static unsigned int
get_ntohl(unsigned char *buf)
{
	return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
}

static unsigned int
get_leohl(unsigned char *buf)
{
	return (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | (buf[0]);
}

static void
put_ntohs(unsigned char *buf, unsigned int val)
{
	buf[0] = val >> 8;
	buf[1] = val;
}

static void
put_ntohl(unsigned char *buf, unsigned int val)
{
	buf[0] = val >> 24;
	buf[1] = val >> 16;
	buf[2] = val >> 8;
	buf[3] = val >> 0;
}

static void
put_leohl(unsigned char *buf, unsigned int val)
{
	buf[3] = val >> 24;
	buf[2] = val >> 16;
	buf[1] = val >> 8;
	buf[0] = val >> 0;
}

static void
fuzz_udp_port(unsigned char *udp_hdr, unsigned short port_no, unsigned short udp_len)
{
	static int a = 1024;

	/* src port */
	put_ntohs(udp_hdr + 0, a);
	a++;

	/* dst port */
	put_ntohs(udp_hdr + 2, port_no);

	put_ntohs(udp_hdr + 4, udp_len);

	memset(udp_hdr + 6, 0, 2);
}


static int
process_filename(const char *proto, const char *filename)
{
	unsigned char buf[2000];
	char fake_buf[2000];

	unsigned int len;
	FILE *fp;

	fp = fopen(filename, "rb");
	if (!fp)
	{
		perror("fopen");
		return 1;
	}

	len = fread(buf, 1, sizeof(buf) - 500, fp);
	fclose(fp);

	if (!strcmp(proto, "udp"))
		write_udp_packet(buf, len);
	else if (!strcmp(proto, "ip"))
		write_ip_packet(buf, len);
	else if (!strcmp(proto, "ip-ospf"))
	{
		write_eth_ip_common(89 /* ospf-igb */, len);
		fwrite(buf, 1, len, stdout);
	}
	else if (!strcmp(proto, "sctp"))
		write_sctp_packet(buf, len);
	else if (!strcmp(proto, "sctp-dtls"))
	{
		memmove(buf + 28, buf, len);

		/* SCTP */
		put_ntohs(buf + 0, 0xAABB);
		put_ntohs(buf + 2, 0xBBCC);
		put_ntohl(buf + 4, 0xAABBBBCC);
		put_ntohl(buf + 8, 0xAAAAAAAA);

		/* SCTP chunk data */
		buf[12] = 0;
		buf[13] = 0x27;
		put_ntohs(buf + 14, 16 + len); /* size */
		put_ntohl(buf + 16, 0x01AAAA00);
		put_ntohs(buf + 20, 0xFFFF);
		put_ntohs(buf + 22, 0);
		put_ntohl(buf + 24, 47 /* DIAMETER_DTLS_PROTOCOL_ID */);

		write_sctp_packet(buf, len + 28);
	}
	else if (!strcmp(proto, "udp-dns"))
	{
		memmove(buf + 8, buf, len);
		fuzz_udp_port(buf, 53, len);
		write_udp_packet(buf, len + 8);
	}
	else if (!strcmp(proto, "udp-bfd"))
	{
		memmove(buf + 8, buf, len);
		fuzz_udp_port(buf, 3784, len);
		write_udp_packet(buf, len + 8);
	}
	else if (!strcmp(proto, "udp-bootp"))
	{
		memmove(buf + 8, buf, len);
		fuzz_udp_port(buf, 67, len);
		write_udp_packet(buf, len + 8);
	}
	else if (!strcmp(proto, "udp-sigcomp"))
	{
		memmove(buf + 8, buf, len);
		fuzz_udp_port(buf, 6666, len);
		write_udp_packet(buf, len + 8);
	}
	else if (!strcmp(proto, "udp-wsp"))
	{
		memmove(buf + 8, buf, len);
		fuzz_udp_port(buf, 9200, len);
		write_udp_packet(buf, len + 8);
	}
	else if (!strcmp(proto, "tcp-bzr"))
	{
		memmove(buf + 20, buf, len);
		fuzz_tcp_port(buf, 4155);
		write_tcp_packet(buf, len + 20);
	}
	else if (!strcmp(proto, "tcp-idmp"))
	{
		unsigned char *pkt = buf;

		while (len >= 6)
		{
			unsigned int pdu_len = 6 + get_ntohl(pkt + 2);

			if (pdu_len >= len) pdu_len = len;

			fuzz_tcp_port(fake_buf, 1102);
			memcpy(fake_buf + 20, pkt, pdu_len);
			put_ntohl(fake_buf + 20 + 2, pdu_len - 6);
			write_tcp_packet(fake_buf, pdu_len + 20);

			pkt += pdu_len;
			len -= pdu_len;
		}
	}
	else if (!strcmp(proto, "tcp-slsk"))
	{
		unsigned char *pkt = buf;

		while (len >= 4)
		{
			unsigned int pdu_len = 4 + get_leohl(pkt);

			if (pdu_len >= len) pdu_len = len;

			fuzz_tcp_port(fake_buf, 2240);
			memcpy(fake_buf + 20, pkt, pdu_len);
			put_leohl(fake_buf + 20, pdu_len - 4);
			write_tcp_packet(fake_buf, pdu_len + 20);

			pkt += pdu_len;
			len -= pdu_len;
		}
	}
	else if (!strcmp(proto, "tcp-pcep"))
	{
		unsigned char *pkt = buf;

		while (len >= 4)
		{
			unsigned int pdu_len = get_ntohs(pkt + 2);

			if (pdu_len >= len) pdu_len = len;

			fuzz_tcp_port(fake_buf, 4189);
			memcpy(fake_buf + 20, pkt, pdu_len);
			put_ntohs(fake_buf + 20 + 2, pdu_len);
			write_tcp_packet(fake_buf, pdu_len + 20);

			pkt += pdu_len;
			len -= pdu_len;
		}
	}
	else if (!strcmp(proto, "tcp-rpki"))
	{
		memmove(buf + 20, buf, len);
		fuzz_tcp_port(buf, 323);
		write_tcp_packet(buf, len + 20);
	}
	else if (!strcmp(proto, "tcp-netsync"))
	{
		memmove(buf + 20, buf, len);
		fuzz_tcp_port(buf, 5253);
		write_tcp_packet(buf, len + 20);
	}
	else if (!strcmp(proto, "tcp-bgp"))
	{
		memmove(buf + 20, buf, len);
		fuzz_tcp_port(buf, 179);
		write_tcp_packet(buf, len + 20);
	}
	else if (!strcmp(proto, "media-json"))
	{
		size_t fake_len;

		/* use HTTP */
		fake_len = snprintf(fake_buf, sizeof(fake_buf), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len);

		memmove(buf + 20 + fake_len, buf, len);
		memcpy(buf + 20, fake_buf, fake_len);
		fuzz_tcp_port(buf, 80);
		write_tcp_packet(buf, len + 20 + fake_len);
	}
	else
	{
		fprintf(stderr, "unknown protocol: %s\n", proto);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *arg_proto;
	int i;

	arg_proto = argv[1];
	if (!arg_proto)
	{
		fprintf(stderr, "Usage: %s <protocol> [input files...]\n", argv[0]);
		return 1;
	}

	/* TODO, convert arg_proto to enum, exit fast if unknown */

	write_pcap();
	for (i = 2; i < argc; i++)
		process_filename(arg_proto, argv[i]);
	return 0;
}
