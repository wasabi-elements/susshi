/*!
 *
 * @brief       TCP Inspection
 *
 * @ingroup     inspection
 *
 * @copyright   Copyright (C) 2026 Wasabi Elements GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * @author      Oliver Rauscher <oliver@susshi.io>
 * @date        2026-02-01
 *
 * @defgroup    inspection_tcp TCP Forwarding Inspection
 * @brief       Functions to inspect tcp forwarding communication.
 *
 * @{
 */

#include "susshid/common.h"


/* Prototypes */
static u_short ip_checksum(unsigned short *packet, int nbytes);
static u_short tcp_checksum(const void *packet, size_t len, in_addr_t src_addr, in_addr_t dest_addr);
static void    write_pcap_global_header(SusshiLog *l);


/*!
 * @brief       Calculate Checksum for IP header
 *
 * @param       packet      Packet starting at IP Header
 * @param       nbytes      Length of IP Header
 * @return      Checksum
 */

static u_short
ip_checksum(unsigned short *packet, int nbytes)
{
	long                sum;
	unsigned short      oddbyte, answer;

	sum = 0L;
	while(nbytes > 1) {
		sum += *packet++;
		nbytes -= 2;
	}

	if(nbytes == 1) {   /* mop up an odd byte if necessary */
		oddbyte = 0;    /* make sure that the top byte is zero */
		*((unsigned char *)&oddbyte) = *(unsigned char *)packet; /* 1 byte only */
		sum += oddbyte;
	}

	/* Now add back carry outs from top 16 bits to lower 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi-16 to lo-16 */
	sum += (sum >> 16);                 /* add carry bits */
	sum = ~sum;
	answer  = (unsigned short) (sum & 0xffff);     /* one's complement, then truncate to 16 bits */
	return(answer);
}


/*!
 * @brief       Calculate TCP Checksum (Header + Pseudo Header + Payload)
 *
 * @param       packet      Packet starting at TCP Header
 * @param       len         Length of TCP + Payload
 * @param       src_addr    IP Source Address
 * @param       dest_addr   IP Destination Address
 * @return      Checksum
 */

static u_short
tcp_checksum(const void *packet, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
	const uint16_t *buf = packet;
	uint16_t *ip_src = (void *) &src_addr, *ip_dst = (void *) &dest_addr;
	uint32_t sum;
	size_t length = len;

	// Calculate the sum
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		// Add the padding if the packet lenght is odd
		sum += *((uint8_t *) buf);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return ((uint16_t) (~sum));
}


/*!
 * @brief       Write a pcap global file header to an encrypted log stream.
 *
 * Used in place of @c pcap_dump_fopen when @c l->enc_state is set.
 * Serialises the 24-byte pcap global header (magic 0xa1b2c3d4, version 2.4,
 * DLT_RAW, snaplen 65535) directly via @c log_session_enc_write so it is
 * stored encrypted.  The byte layout matches what libpcap would write for
 * native-endian, microsecond-resolution pcap files.
 *
 * @param[in,out] l   Log whose encrypted stream should receive the header.
 */

static void
write_pcap_global_header(SusshiLog *l)
{
    struct {
        uint32_t magic;
        uint16_t major;
        uint16_t minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t linktype;
    } hdr;

    hdr.magic    = 0xa1b2c3d4;
    hdr.major    = 2;
    hdr.minor    = 4;
    hdr.thiszone = 0;
    hdr.sigfigs  = 0;
    hdr.snaplen  = 0xffff;
    hdr.linktype = DLT_RAW;
    log_session_enc_write(l, (const unsigned char *)&hdr, sizeof(hdr));
}


/*!
 * @brief       Write bytestream traffic to PCAP file by adding pseudo information:
 *
 * IP address, Source and Destion Ports are set upfront by packet inspection module
 *
 * @param       cid         Channel ID
 * @param       sender      Side this bytestream packet comes from
 * @param       datastr     The SSH Datastring
 */

void
do_log_tcp(int cid, Side sender, ssh_string datastr) {

	SusshiChannel *c;
	SusshiLog *l;

	const char *data = NULL;
	size_t datalen;

	u_char *pkt = NULL;
	struct ip *pkt_ip;
	struct tcphdr *pkt_tcp;
	struct pcap_pkthdr pcap_pkt_header;
	struct {
		uint32_t ts_sec;
		uint32_t ts_usec;
		uint32_t incl_len;
		uint32_t orig_len;
	} pcap_rechdr;

	if ((c = susshi_session.channels[cid]) != NULL) {
		if ((l = &c->log_protocol) != NULL) {

			// --- Open logfile if required
			if (c->log_protocol.fd == NULL) {
				susshi_open_logfile(&c->log_protocol);
				if (!l->enc_state)
					l->pcap = pcap_open_dead(DLT_RAW, 0xffff);

				// Initialize starting sequence numbers with timestamp
				l->pcap_tcp_client_seq = (tcp_seq) time(NULL);
				l->pcap_tcp_target_seq = ~l->pcap_tcp_client_seq;

				if (l->filesize == 0) {
					// File opened for the first time, so write the pcap global header
					if (l->enc_state) {
						write_pcap_global_header(l);
					} else {
						if ((pcap_dump_fopen(l->pcap, l->fd) == NULL))
							return;
					}
				}
			}

			gettimeofday(&pcap_pkt_header.ts, NULL);

			// Re-open logfile if we run into next period
			if (pcap_pkt_header.ts.tv_sec > c->log_protocol.next_period) {
				susshi_open_logfile(&c->log_protocol);

				if (l->filesize == 0) {
					// New file after rotation, so write the pcap global header
					if (l->enc_state) {
						write_pcap_global_header(l);
					} else {
						if ((pcap_dump_fopen(l->pcap, l->fd) == NULL))
							return;
					}
				}
			}

			data = ssh_string_get_char(datastr);
			datalen = ssh_string_len(datastr);

			debug_susshi_hexdump(data, datalen);

			/*
			 * pkt_header + pkt gets written to pcap file
			 */

			pcap_pkt_header.len = (bpf_u_int32 ) datalen + 40;	// Add IP (20 bytes) and TCP (20 bytes) headers
			pcap_pkt_header.caplen = pcap_pkt_header.len;

			pkt = malloc(pcap_pkt_header.len);
			memset(pkt, 0, 40);

			/* Offsets on pkt */
			pkt_ip = (struct ip *) pkt;
			pkt_tcp = (struct tcphdr *) (pkt + 20);

			// --- TCP Header ---

			pkt_tcp->th_off = 5;    // number of 32-Bit words
			pkt_tcp->th_win = 0xffff;
			pkt_tcp->th_flags = TH_ACK;

			// --- IP HEADER ---
			pkt_ip->ip_id = htons(l->pcap_ip_id++);
			pkt_ip->ip_v = 4;
			pkt_ip->ip_hl = 5;
			pkt_ip->ip_len = htons(datalen + 40);
			pkt_ip->ip_ttl = 64;
			pkt_ip->ip_p = IPPROTO_TCP;

			if (sender == CLIENT) {

				// --- IP HEADER ---
				pkt_ip->ip_src.s_addr = htonl(c->client_forward_in_addr.s_addr);
				pkt_ip->ip_dst.s_addr = htonl(c->target_forward_in_addr.s_addr);

				// --- TCP Header ---
				pkt_tcp->th_sport = htons(c->client_forward_port);
				pkt_tcp->th_dport = htons(c->target_forward_port);
				pkt_tcp->th_seq = htonl(l->pcap_tcp_client_seq);
				pkt_tcp->th_ack = htonl(l->pcap_tcp_target_seq);

				// --- Payload ---
				memcpy(pkt + 40, data, datalen);

				// --- TCP Checksum ---
				pkt_tcp->th_sum = tcp_checksum(pkt_tcp, datalen + 20, htonl(c->client_forward_in_addr.s_addr), htonl(c->target_forward_in_addr.s_addr));

				l->pcap_tcp_client_seq+=datalen;

			} else {

				// --- IP HEADER ---
				pkt_ip->ip_src.s_addr = htonl(c->target_forward_in_addr.s_addr);
				pkt_ip->ip_dst.s_addr = htonl(c->client_forward_in_addr.s_addr);

				// --- TCP Header ---
				pkt_tcp->th_sport = htons(c->target_forward_port);
				pkt_tcp->th_dport = htons(c->client_forward_port);
				pkt_tcp->th_seq = htonl(l->pcap_tcp_target_seq);
				pkt_tcp->th_ack = htonl(l->pcap_tcp_client_seq);

				// --- Payload ---
				memcpy(pkt + 40, data, datalen);

				// --- TCP Checksum ---
				pkt_tcp->th_sum = tcp_checksum(pkt_tcp, datalen + 20, htonl(c->target_forward_in_addr.s_addr), htonl(c->client_forward_in_addr.s_addr));

				l->pcap_tcp_target_seq+=datalen;

			}

			// --- IP Checksum ---
			pkt_ip->ip_sum = ip_checksum((u_short *) pkt_ip, 20);

			if (l->enc_state) {
				pcap_rechdr.ts_sec   = (uint32_t)pcap_pkt_header.ts.tv_sec;
				pcap_rechdr.ts_usec  = (uint32_t)pcap_pkt_header.ts.tv_usec;
				pcap_rechdr.incl_len = pcap_pkt_header.caplen;
				pcap_rechdr.orig_len = pcap_pkt_header.len;
				log_session_enc_write(l, (const unsigned char *)&pcap_rechdr, sizeof(pcap_rechdr));
				log_session_enc_write(l, pkt, pcap_pkt_header.caplen);
			} else {
				pcap_dump((u_char *) l->fd, &pcap_pkt_header, pkt);
			}

			debug4("Recorded %ld bytes in pcap file.", datalen + 40);

			xfree(pkt);
		}
	}

}


/*!
 * @brief       Inspect Port Forwarding Data
 *
 * @param       cid             Channel ID
 * @param       sender          Side this bytestream packet comes from
 * @param       buffer_copy     A copy of the packet
 *
 * @return      Return true if forwarding has not been filtered, otherwise false
 */

bool
susshi_inspect_pfwd_data(int cid, Side sender, ssh_buffer buffer_copy) {

	ssh_string datastr = NULL;

	if (ssh_buffer_unpack(buffer_copy, "S", &datastr) != SSH_OK) {
		fatal("Packet decoding returned with fatal error: Inspect Port Forwarding Data.");
	}

	/*
	 * Check for SSH tunneling through TCP forward
	 */
	if (susshi_session.tcp_forward_ssh_allowed == false) {
		SusshiChannel *c;

		c = susshi_session.channels[cid];

		if (((c = susshi_session.channels[cid]) != NULL) && (c->requestor_send == 0)) {
			if (strncmp(ssh_string_get_char(datastr), "SSH-", (size_t) MIN(4, ssh_string_len(datastr))) == 0) {
				log_session(sender, TheOtherSide(sender), "Forwarding SSH session through TCP Forward denied by ACL.");
				SSH_STRING_FREE(datastr);
				return false;
			}
		}
	}

	do_log_tcp(cid, sender, datastr);
	SSH_STRING_FREE(datastr);
	return true;
}

/*! @} */
