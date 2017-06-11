/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#include "dns.h"

#include "byte_range.h"
#include <stdlib.h>
#include <arpa/inet.h>

static
int parse_name(byte_range * buf, byte_range * name)
{
	uint8_t * name_org;
	uint8_t len;

	name_org = name->ptr;

	for (;;)
	{
		if (buf->ptr == buf->end)
			return -1;

		len = *buf->ptr++;
		if (len == 0)
			break;

		if ((len & 0xC0) == 0xC0)
		{
			if (buf->ptr + 1 > buf->end)
				return -1;

			buf->ptr++;
			break;
		}

		/*
		 *
		 */
		if (buf->ptr + len > buf->end)
			return -1;

		if (name->ptr + len + 2 > name->end) /* +2 is for \0 and . */
			return -1;

		if (name->ptr > name_org)
			*(name->ptr++) = '.';

		memcpy(name->ptr, buf->ptr, len);
		name->ptr += len;
		buf->ptr += len;
	}
	*(name->ptr) = 0;

	/*
	 *
	 */
	name->end = name->ptr;
	name->ptr = name_org;
	br_to_lower(name);

	return 0;
}

static
int parse_question(byte_range * buf, dns_question * q)
{
	byte_range name;

	memset(q, 0, sizeof(*q));

	/*
	 *
	 */
	name.ptr = q->name;
	name.end = q->name + sizeof(q->name);

	if (parse_name(buf, &name) < 0)
		return -1;

	/*
	 *
	 */
	if (buf->ptr + 4 > buf->end)
		return -1;

	q->type   = htons( *(uint16_t*)buf->ptr );
	q->class_ = htons( *(uint16_t*)(buf->ptr+2) );

	buf->ptr += 4;

	return 0;
}

static
int parse_rr(byte_range * buf, dns_rr * rr)
{
	byte_range name;

	memset(rr, 0, sizeof(*rr));

	/*
	 *
	 */
	name.ptr = rr->name;
	name.end = rr->name + sizeof(rr->name);

	if (parse_name(buf, &name) < 0)
		return -1;

	/*
	 *
	 */
	if (buf->ptr + 10 > buf->end)
		return -1;

	rr->type   = htons( *(uint16_t*)buf->ptr );
	rr->class_ = htons( *(uint16_t*)(buf->ptr+2) );
	rr->ttl    = htonl( *(uint32_t*)(buf->ptr+4) );
	rr->len    = htons( *(uint16_t*)(buf->ptr+8) );
	rr->data   = buf->ptr + 10;

	if (buf->ptr + 10 + rr->len > buf->end)
		return -1;

	buf->ptr += 10 + rr->len;
	return 0;
}

/*
 *
 */
int dns_get_question(const dns_header * hdr, size_t len, size_t q_index, dns_question * q)
{
	byte_range buf;
	size_t q_count;

	q_count = htons(hdr->qcount);

	if (q_index >= q_count || len < sizeof(*hdr))
		return -1;

	buf.ptr = (uint8_t *)hdr;
	buf.end = buf.ptr + len;

	buf.ptr += sizeof(*hdr);
	do
	{
		if (parse_question(&buf, q) < 0)
			return -1;
	}
	while (q_index--);

	return 0;
}

int dns_get_answer(const dns_header * hdr, size_t len, size_t a_index, dns_rr * a)
{
	byte_range buf;
	dns_question foo;
	size_t i, q_count, a_count;;

	q_count = htons(hdr->qcount);
	a_count = htons(hdr->acount);

	if (a_index >= a_count || len < sizeof(*hdr))
		return -1;

	buf.ptr = (uint8_t *)hdr;
	buf.end = buf.ptr + len;

	buf.ptr += sizeof(*hdr);

	for (i = 0; i < q_count; i++)
		if (parse_question(&buf, &foo) < 0)
			return -1;

	do
	{
		if (parse_rr(&buf, a) < 0)
			return -1;
	}
	while (a_index--);

	return 0;
}

static size_t dns_get_label(const dns_header *hdr, size_t hdr_len, char *ptr, char *str, size_t str_size)
{
    int len;
    int res;
    int count = 0;
    char *itr = ptr;
    while (len = *itr) {
        if (*itr & 0xc0) {
            int p = htons(*(uint16_t *)itr) & 0x3fff;
            res = dns_get_label(hdr, hdr_len, ((char *)hdr)+p, str, str_size);
            len = 2;
        } else {
            res = snprintf(str, str_size, "%.*s.", len, itr+1);
        }
        str += res;
        count += res;
        str_size -= res;
        if (str_size < 0) break;

        itr += len + 1;
    }

    return count;
}

void dump_dns_response(const dns_header * hdr, size_t len)
{
	size_t i, q_count, a_count;

	q_count = htons(hdr->qcount);
	a_count = htons(hdr->acount);

	printf("\n");
	for (i=0; i<len; i++)
	{
		printf("%02x ", 0xff & *(i + (char*)hdr));
		if ((i & 0xf) == 0xf)
			printf("\n");
	}

	printf("\n");

	printf("ID        0x%04hx\n", htons(hdr->id));
	printf("flags     0x%04hx\n", htons(hdr->flags));
	printf("q_count   %lu\n", q_count);
	printf("a_count   %lu\n", a_count);
	printf("ns_count  %hu\n", htons(hdr->nscount));
	printf("ar_count  %hu\n", htons(hdr->arcount));

	for (i=0; i < q_count; i++)
	{
		dns_question q;
		if (dns_get_question(hdr, len, i, &q) < 0)
		{
			printf("Failed to parse Q[%lu]\n", i);
			return;
		}

		printf("\n   Q%lu\n", i+1);
		printf("   Name   [%s]\n", q.name);
		printf("   Type   0x%04x\n", q.type);
		printf("   Class  0x%04x\n", q.class_);
	}

	for (i=0; i < a_count; i++)
	{
		dns_rr a;
		if (dns_get_answer(hdr, len, i, &a) < 0)
		{
			printf("Failed to parse A[%lu]\n", i);
			return;
		}

		printf("\n   A%lu\n", i+1);
		printf("   Name   [%s]\n", a.name);
		printf("   Type   0x%04x\n", a.type);
		printf("   Class  0x%04x\n", a.class_);
		printf("   TTL    %u\n", a.ttl);
		printf("   Bytes  %hu\n", a.len);
        if (a.type == 1) {
            printf("   %s\n", inet_ntoa(*(struct in_addr *)a.data));
        } else if (a.type == 5) {
            char str[512];
            dns_get_label(hdr, len, a.data, str, sizeof(str));
            printf("%s\n", str);
        }
	}
}

void get_dns_req_reply(const dns_header * hdr, size_t len, char *str, size_t str_size, struct in_addr *client)
{
	size_t i, q_count, a_count;
    int res;

	q_count = htons(hdr->qcount);
	a_count = htons(hdr->acount);

	res = snprintf(str, str_size, "%s - ", inet_ntoa(*(struct in_addr *)client));
    str += res;
    str_size -= res;
    if (str_size < 0) return;

	res = snprintf(str, str_size, "(0x%04hx, 0x%04hx, %lu, %lu, %hu, %hu) ", 
                    htons(hdr->id), htons(hdr->flags), q_count, a_count, htons(hdr->nscount), htons(hdr->arcount));

    str += res;
    str_size -= res;
    if (str_size < 0) return;

	for (i=0; i < q_count; i++)
	{
		dns_question q;
		if (dns_get_question(hdr, len, i, &q) < 0)
		{
			printf("Failed to parse Q[%lu]\n", i);
			return;
		}

	    res = snprintf(str, str_size, "Q%lu:%s,0x%04x,0x%04x ", i+1, q.name, q.type, q.class_);
        str += res;
        str_size -= res;
        if (str_size < 0) return;
	}

	for (i=0; i < a_count; i++)
	{
		dns_rr a;
		if (dns_get_answer(hdr, len, i, &a) < 0)
		{
			printf("Failed to parse A[%lu]\n", i);
			return;
		}

	    res = snprintf(str, str_size, "A%lu:[%s],0x%04x,0x%04x ", i+1, a.name, a.type, a.class_);
        str += res;
        str_size -= res;
        if (str_size < 0) return;

        if (a.type == 1) {
	        res = snprintf(str, str_size, "%s ", inet_ntoa(*(struct in_addr *)a.data));
            str += res;
            str_size -= res;
            if (str_size < 0) return;
        } else if (a.type == 5) {
            res = dns_get_label(hdr, len, a.data, str, str_size);
            str += res;
            str_size -= res;
            if (str_size < 0) return;

            if (str_size >= 2) {
                strcpy(str, " ");
                str += 1;
                str_size -= 1;
            }
        }
	}
}

