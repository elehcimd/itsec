/*
 * main.h by xenion -- Sun Nov 18 21:40:03 CET 2007
 *
 * Copyright (c) 2007 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


/* const */

#define DEFAULT_OUTDIR "."
#define HTTP_COOKIE_VALUES_MAX 100
#define HTTP_COOKIE_OPTIONS_MAX 100
#define HTTP_COOKIES_MAX 100
#define HTTP_HEADERS_MAX 100
#define HTTP_PACKETS_PER_HEADER_MAX 5
#define PCAP_SNAPLEN 65535

#define HTTP_COOKIE_DEFAULT_EXPIRES "Tuesday, 2-Feb-2020 02:02:02 GMT"
#define HTTP_COOKIE_DEFAULT_PATH "/"


/* types */

typedef struct
  {
    char *rxfile;
    char *iface;
    int dllength;
    char *mypcap_filter;
    int savepcap;
    int promisc;
    char *outdir;
    int stdout;
    int daemonize;
    char *user;
    int verbose;
    int syslog;
    int handle1pkt;
  }
OPT;

typedef struct
  {
#define ADDRS_TYPE_UNKNOWN 0
#define ADDRS_TYPE_IP 1
#define ADDRS_TYPE_TCP 2
#define ADDRS_TYPE_UDP 3
    int type;
    u_int32_t srcaddr;
    u_int32_t dstaddr;
    u_int16_t srcport;
    u_int16_t dstport;
  }
addrs_t;

typedef struct
  {
    int set;
    char *expires;
    char *path;
    char *domain;
    char *values[HTTP_COOKIE_VALUES_MAX][2]; // NAME is values[i][0], VALUE is values[i][1]
    char *options[HTTP_COOKIE_OPTIONS_MAX];
    int values_count;
    int options_count;
  }
cookie_t;

typedef struct
  {
    char *startline;
    char *headers[HTTP_HEADERS_MAX][2];
    cookie_t cookies[HTTP_COOKIES_MAX];
    int cookies_count;
    int headers_count;
    int32_t content_length;
    char *header_host;
    int chunked_transfer_encoding;
  } http_message_t;

typedef struct
  {
    int pkts;
    int32_t len_discard;
    int32_t len;
  } tcp_data_t;

typedef struct
  {
    int new;
    addrs_t addrs;
    tcp_data_t client;
    tcp_data_t server;
    u_int32_t cookies_count;
    int desync;
  } http_conn_t;


typedef struct
  {
    u_int32_t cookies_count;
    u_int32_t dropped_chunked_count;
    u_int32_t dropped_parsing_count;
    u_int32_t http_conns_active_count;
    u_int32_t http_conns_closed_count;
    u_int32_t http_conns_total_count;
    u_int32_t http_conns_desync_count;
    u_int32_t http_conns_sync_count;
    u_int32_t http_conns_resync_count;
  } stats_t;

/* EOF */

