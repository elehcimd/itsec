/*
 * main.c by xenion -- Sun Nov 18 21:40:03 CET 2007
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


/* includes */

#include <time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <nids.h>
#include "common.h"
#include "net.h"
#include "main.h"


/* globals */

pcap_t *mypcap = NULL;
char errbuf[PCAP_ERRBUF_SIZE];
OPT o;
int32_t ndxlog = -1;
struct timeval pcap_time;
u_int32_t pktcount = 0;
stats_t stats;
int running = 0;
int tcp_callback_called = 0;
int invert_addrs = 0;
pcap_dumper_t *pcap_dumper = NULL;


/* protos */

void tcp_callback(struct tcp_stream * ns, void ** param);
int dissect_ieee80211(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_eth(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_ip(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_tcp(struct pcap_pkt *ppkt,u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs);
void loop(int dlltype,int dllength);
int parse_http_header(char *str, char **name, char **value);
int parse_http_cookie(cookie_t *cookie, int type,char *str);
int handle_http_message(http_message_t *http_message, addrs_t addrs);
int seems_http_header(char *data, u_int32_t datalen);
int parse_http_message(char *data, u_int32_t datalen, http_message_t *http_message);
void disable_nids_chksum();
int main(int argc, char **argv);
void init_opt(int argc, char **argv);
void help();
void cleanup();
void sig_stats_handler(int signo);
int inject_tcp_open3way(struct pcap_pkt *ppkt);
int inject_tcp_pkt(struct pcap_pkt *ppkt, u_int32_t ip_src, u_int32_t ip_dst,u_int16_t port_src, u_int16_t port_dst, u_int32_t tcp_seq, u_int32_t tcp_ack, u_int8_t tcp_flags);


/* extern */


/*******************************************/


void syslog_libnids(int type, int err, struct ip *iph, void *data)
{
  LOG(1,1," * libnids (pktcount=%d): %s",pktcount, nids_warnings[err]);
}


int dissect_eth(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  struct libnet_ethernet_hdr *eth;


  if (pktlen < sizeof(struct libnet_ethernet_hdr))
    {
      LOG(1,1," * warning: broken eth frame");
      return 0;
    }

  eth = (struct libnet_ethernet_hdr *)(ppkt->pkt+pktoff);

  if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
      return dissect_ip(ppkt,sizeof(struct libnet_ethernet_hdr),ppkt->hdr.caplen-sizeof(struct libnet_ethernet_hdr));

    }

  return 0;
}


int dissect_ieee80211(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  struct ieee80211_frame *wh;
  int32_t len;


  if (pktlen < sizeof(struct ieee80211_frame))
    {
      LOG(1,1," * warning: broken ieee 802.11 frame");
    }

  wh = (struct ieee80211_frame *)(ppkt->pkt+pktoff);

  len = sizeof(struct ieee80211_frame);

  if ((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA)
    return 0;

  if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
    len += IEEE80211_ADDR_LEN;
  if (IEEE80211_QOS_HAS_SEQ(wh))
    len += sizeof(u_int16_t);

  len+=8;

  if (len > pktlen) // this packet is something not interesting
    {
      return 0;
    }

  if ( ntohs(*((int32_t *)&ppkt->pkt[len-2])) == ETHERTYPE_IP)
    return dissect_ip(ppkt,len,ppkt->hdr.caplen-len);

  return 0;
}


int dissect_ip(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  addrs_t addrs = { 0,0,0,0};
  struct libnet_ipv4_hdr *pktip;
  int32_t len;


  if (pktlen < sizeof(struct libnet_ipv4_hdr))
    {
      LOG(1,1," * warning: broken ip packet");
      return 0;
    }

  pktip = (struct libnet_ipv4_hdr *) (ppkt->pkt + pktoff);

  len = ntohs(pktip->ip_len) - (pktip->ip_hl << 2);

  // nota: potrebbe esserci il trailer eth

  if (len < 0 || len > pktlen)
    {
      LOG(1,1," * warning: broken ip packet");
      return 0;
    }

  addrs.srcaddr = pktip->ip_src.s_addr;
  addrs.dstaddr = pktip->ip_dst.s_addr;

  if (pktip->ip_p == IPPROTO_TCP)
    return dissect_tcp(ppkt,pktoff+(pktip->ip_hl << 2),len,addrs);
  return 0;
}


int dissect_tcp(struct pcap_pkt *ppkt,u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs)
{
  struct libnet_tcp_hdr *pkttcp;
  int32_t len;
  struct tuple4 addr;
  int z,found;
  u_int32_t tmp;
  http_message_t http_message;


  if (pktlen < sizeof(struct libnet_tcp_hdr))
    return 0;

  pkttcp = (struct libnet_tcp_hdr *) (ppkt->pkt +  pktoff);

  len = pktlen - pkttcp->th_off * 4;

  if (len < 0 )return 0;

  addrs.type = ADDRS_TYPE_TCP;
  addrs.srcport = ntohs(pkttcp->th_sport);
  addrs.dstport = ntohs(pkttcp->th_dport);


  addr.saddr = addrs.srcaddr;
  addr.daddr = addrs.dstaddr;
  addr.source = addrs.srcport;
  addr.dest = addrs.dstport;

  //LOG(1,0,"TCP PACKET from %s:%d to ",INET_NTOA(addrs.srcaddr),addrs.srcport);
  //LOG(0,1,"%s:%d, %d bytes",INET_NTOA(addrs.dstaddr),addrs.dstport,len);

  if (len == 0)
    return 0;

  z = seems_http_header((char *)ppkt->pkt +pktoff+pkttcp->th_off * 4,len);
  if (z == 0) // it doesn't seem http
    return 0;

  found = 0;

  addr.daddr = addrs.srcaddr;
  addr.saddr = addrs.dstaddr;
  addr.dest = addrs.srcport;
  addr.source = addrs.dstport;

  if (nids_find_tcp_stream(&addr))
    found++;

  addr.saddr = addrs.srcaddr;
  addr.daddr = addrs.dstaddr;
  addr.source = addrs.srcport;
  addr.dest = addrs.dstport;

  if (nids_find_tcp_stream(&addr))
    found++;

  tcp_callback_called = 0; // required also if found > 0 !! used later.

  if (found == 0) // already existing connection, not registered in libnids!
    {
      VLOG(1,1," * detected already existing HTTP connection, faking 3way handshake...");
      //VLOG(1,0," * HTTP pkt from %s:%d to ",INET_NTOA(addrs.srcaddr),addrs.srcport);
      //VLOG(0,1,"%s:%d, %d bytes",INET_NTOA(addrs.dstaddr),addrs.dstport,len);

      invert_addrs = z == 2 ? 1 : 0; // client or server http message? ...
      inject_tcp_open3way(ppkt);
      invert_addrs = 0;
      tcp_callback_called = 0;
      nids_pcap_handler(0,&ppkt->hdr, ppkt->pkt);
    }

  if (tcp_callback_called == 0)  // seems http but libnids maybe didn't recognize it correctly... gather as much as possible from this single packet! if handle1pkt option is active.
    {
      if (o.handle1pkt)
        {
          LOG(1,0," ! handling single HTTP pkt: %s:%d > ",INET_NTOA(addrs.srcaddr),addrs.srcport);
          LOG(0,1,"%s:%d",INET_NTOA(addrs.dstaddr),addrs.dstport);

          if (z == 2)  // we must invert addrs...
            {
              SWITCH_VALUES(addrs.srcaddr, addrs.dstaddr, tmp);
              SWITCH_VALUES(addrs.srcport, addrs.dstport, tmp);
            }

          z = parse_http_message((char *)ppkt->pkt + pktoff + pkttcp->th_off * 4, len, &http_message);

          if ( http_message.cookies_count >0 || http_message.headers_count >0)
            {
              handle_http_message(&http_message, addrs);
              stats.cookies_count+= http_message.cookies_count;
            }
        }
    }

  return 0;
}


void tcp_callback(struct tcp_stream * ns, void ** param)
{
  struct half_stream *hlf;
  http_conn_t *http_conn;
  http_message_t http_message;
  int32_t len, off, i;
  tcp_data_t *data;


  tcp_callback_called = 1;

  http_conn = (http_conn_t * )*param;

//  VLOG(1,1," * here");


  switch (ns->nids_state)
    {
    case NIDS_JUST_EST:

      ns->client.collect =1; // we want data received by a client
      ns->server.collect =1; // and by a server, too

      http_conn = malloc(sizeof(http_conn_t));
      if (!invert_addrs)
        {
          http_conn->addrs.srcaddr = ns->addr.saddr;
          http_conn->addrs.dstaddr = ns->addr.daddr;
          http_conn->addrs.srcport = ns->addr.source;
          http_conn->addrs.dstport = ns->addr.dest;
        }
      else
        {
          http_conn->addrs.srcaddr = ns->addr.daddr;
          http_conn->addrs.dstaddr = ns->addr.saddr;
          http_conn->addrs.srcport = ns->addr.dest;
          http_conn->addrs.dstport = ns->addr.source;
        }
      http_conn->new = 1;
      http_conn->desync = 0;
      memset(&http_conn->server,0,sizeof(http_conn->server));
      memset(&http_conn->client,0,sizeof(http_conn->client));
      *param = http_conn;

      VLOG(1,0," * detected TCP conn: %s:%d > ",INET_NTOA(http_conn->addrs.srcaddr),http_conn->addrs.srcport);
      VLOG(0,1,"%s:%d",INET_NTOA(http_conn->addrs.dstaddr),http_conn->addrs.dstport);
      break;

    case NIDS_EXITING:
    case NIDS_CLOSE:
    case NIDS_RESET:
    case NIDS_TIMED_OUT:
      if (http_conn && http_conn->new == 0)
        {
          stats.http_conns_active_count--;
          stats.http_conns_closed_count++;
          if (http_conn->desync)
            stats.http_conns_desync_count--;
          else
            stats.http_conns_sync_count--;
        }

      SAFE_FREE(*param);
      break;

    case NIDS_DATA:
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      if (http_conn == NULL)
        FATAL("http_conn == NULL");

      if (ns->client.count_new)
        {
          hlf = &ns->client;
          data = &http_conn->client;
        }
      else   // can be only ns->server.count_new ...
        {
          hlf = &ns->server;
          data =&http_conn->server;
        }

      if (http_conn->new && seems_http_header(hlf->data, hlf->count_new) == 0)
        break; // remains new, in state "maybe http".

      if (http_conn->new)  // is new and seems http...
        {
          http_conn->new=0;
          LOG(1,0," ! observing HTTP conn: %s:%d >",INET_NTOA(http_conn->addrs.srcaddr),http_conn->addrs.srcport);
          LOG(0,1," %s:%d",INET_NTOA(http_conn->addrs.dstaddr),http_conn->addrs.dstport);
          stats.http_conns_active_count++;
          stats.http_conns_sync_count++;
        }

      data->len+= hlf->count_new;

      i = 0;
      if (data->len >0 && data->len_discard >0)
        {
          i = MIN(data->len, data->len_discard);
          data->len -= i;
          data->len_discard -= i;
        }

      len= data->len;
      off = i;

      if (len < 0)
        FATAL("len < 0, should not happen");
      if (len == 0)
        break;

//      LOG(1,0,"pkt of tcp connection from %s:%d to ",INET_NTOA(http_conn->addrs.srcaddr),http_conn->addrs.srcport);
//      LOG(0,1,"%s:%d",INET_NTOA(http_conn->addrs.dstaddr),http_conn->addrs.dstport);

      if (seems_http_header(hlf->data+off, len) == 0)
        {
          // HTTP conn. desynchronized!
          if (http_conn->desync == 0)
            {
              stats.http_conns_desync_count++;
              stats.http_conns_sync_count--;
              http_conn->desync =1;
            }
          data->len = 0;
          data->len_discard = 0;
          break;
        }
      else
        {
          if (http_conn->desync == 1)
            {
              // was desync, now sync!
              http_conn->desync = 0;
              stats.http_conns_desync_count--;
              stats.http_conns_sync_count++;
              stats.http_conns_resync_count++;
            }
        }


      if ((i = parse_http_message(hlf->data+off, len, &http_message)) == -1)
        {
          // parsing failed!

          if ((http_message.cookies_count >0 || http_message.headers_count >0) && o.handle1pkt)
            {
              handle_http_message(&http_message, http_conn->addrs);
              stats.cookies_count+= http_message.cookies_count;
            }

          if (data->pkts >= HTTP_PACKETS_PER_HEADER_MAX)
            {
              // abbiamo gia' tenuto il pkt precedente nel buffer,
              // anche con questo non abbiamo un http message header
              // valido e completo.

              stats.http_conns_desync_count++;
              stats.http_conns_sync_count--;
              http_conn->desync =1;
              data->len = 0;
              data->len_discard = 0;
              break;

            }
          else
            {
              // not full header present! needs also next packet....
              data->pkts++;
              nids_discard(ns, 0);
            }
          break;
        }
      else
        {
          data->pkts = 0;
          data->len-= i;
          off+=i;
          if (data->len < 0)
            FATAL("remaining len < 0");
          handle_http_message(&http_message, http_conn->addrs);
          stats.cookies_count+= http_message.cookies_count;

          data->len_discard = MAX(0,http_message.content_length);

          i = 0;
          if (data->len >0 && data->len_discard >0)
            {
              i = MIN(data->len, data->len_discard);
              data->len -= i;
              data->len_discard -= i;
            }

          len= data->len;
          off += i;

// ignoriamo il buffer rimanente, che probabilmente contiene un content del quale
// non siamo in grado di calcolare la lunghezza. se finisce in questo pkt, allora
// il prossimo verra' parsato correttamente. altrimenti, comunque meglio di cosi'
// non potevamo fare. scelta greedy :)

          break;
        }
      break;
    default:
      LOG(1,1," * warning: not recognized libnids state, should never happen");
    }
}


void loop(int dlltype,int dllength)
{
  struct pcap_pkt ppkt;


  ppkt.dllength = dllength;
  ppkt.dlltype = dlltype;

  for (;;)
    {
      ppkt.pkt = (u_int8_t *)pcap_next(mypcap, &ppkt.hdr);

      if (!ppkt.pkt)
        {
          if (o.iface)
            continue;

          if (o.rxfile)
            {
              LOG(1,1," * eof reached.");
              break;
            }
        }

      pcap_time = ppkt.hdr.ts;

      pktcount++;
      //LOG(1,1,"pktcount: %d", pktcount);

      tcp_callback_called = 0;
      nids_pcap_handler(0,&ppkt.hdr, ppkt.pkt);

      if (tcp_callback_called == 0 && o.handle1pkt)
        {
          switch (dlltype)
            {
            case AP_DLT_EN10MB:
              dissect_eth(&ppkt,0,ppkt.hdr.caplen);
              break;
            case AP_DLT_IEEE802_11:
              dissect_ieee80211(&ppkt,0,ppkt.hdr.caplen);
              break;
            default:
              dissect_ip(&ppkt,dllength,ppkt.hdr.caplen-dllength); //skip header and try...
            }
        }

      if (pcap_dumper)
        pcap_dump((u_int8_t *) pcap_dumper, &ppkt.hdr, ppkt.pkt);
    }
}


int parse_http_header(char *str, char **name, char **value)
{
  int32_t i, len, off;


  off=0;
  len=strlen(str);

//  LOG(1,1,"input '%s'", str);


  if ((i = parse_token(str, len, ":",NULL)) == -1)
    return -1;

  *name = trim(str);
  *value = trim(str+i);

//LOG(1,1,"parse_http_header '%s' '%s'", *name, *value);

  return 0;
}


int parse_http_cookie(cookie_t *cookie, int type,char *str)
{
  int32_t i, len, off, len1,off1;
  char *name, *value;


  cookie->set = type;
  cookie->values_count = 0;
  cookie->options_count = 0;
  cookie->expires= NULL;
  cookie->path= NULL;
  cookie->domain= NULL;

// format: "Set-Cookie: NAME=VALUE; expires=DATE; path=PATH; domain=DOMAIN_NAME; option2"
//         "Cookie: NAME1=VALUE1; NAME2=VALUE2; ..."

//LOG(1,1,"parsing cookie: type %d str '%s'", type,str);


  off=0;
  len = strlen(str);


  for (;len > 0;)
    {
      off1=off;
      len1=len;

// skip to next option/name=value ...

      if ((i = parse_token(&str[off], len, ";",NULL)) != -1)
        {
          off+=i;
          len-=i;
        }
      else
        {
          off+=len;
          len = 0;
        }

// from here, we use off1,len1.

      if ((i = parse_token(&str[off1],len1, "=",NULL)) == -1)
        {
          // opzione
          if (cookie->options_count >= HTTP_COOKIE_OPTIONS_MAX)
            {
              LOG(1,1," * warning: too many http cookie options!");
              continue;
            }
          cookie->options[cookie->options_count] = trim(&str[off1]);
//     LOG(1,1,"option: '%s'", cookie->options[cookie->options_count]);

          cookie->options_count++;
        }
      else
        {
          //name=value
          name=trim(&str[off1]);
          value=trim(&str[off1+i]);

          if (strncasecmp(name, "expires", STATIC_STRLEN("expires")) == 0)
            cookie->expires = value;
          else
            if (strncasecmp(name, "path", STATIC_STRLEN("path")) == 0)
              cookie->path = value;
            else
              if (strncasecmp(name, "domain", STATIC_STRLEN("domain")) == 0)
                cookie->domain = value;
              else
                {
                  if (cookie->values_count >= HTTP_COOKIE_VALUES_MAX)
                    {
                      LOG(1,1," * warning: too many http cookie values!");
                      continue;
                    }

                  cookie->values[cookie->values_count][0] = name;
                  cookie->values[cookie->values_count][1] = value;
//    LOG(1,1,"value: '%s'='%s'", cookie->values[cookie->values_count][0],cookie->values[cookie->values_count][1]);
                  cookie->values_count++;
                }
        }
    }

//LOG(1,1,"parsing cookie ok");
  return 0;
}


int handle_http_message(http_message_t *http_message, addrs_t addrs)
{
  int32_t i,j,k;
  char pathname[PATH_MAX];
  char srcaddr[15+1], dstaddr[15+1]; // space for 1 0terminated ip: iii.iii.iii.iii0
  FILE *f;
  char *p,*q;


  strcpy(srcaddr, INET_NTOA(addrs.srcaddr));
  strcpy(dstaddr, INET_NTOA(addrs.dstaddr));

  snprintf(pathname, PATH_MAX, "%s/%s-%s.txt", o.outdir, srcaddr, dstaddr);

  if ((f =  fopen(pathname, "a")) == NULL)
    FATAL("fopen(): %s", strerror(errno));

  fprintf(f, "pktcount=%d time=%s.%ld src=%s:%d dst=%s:%d\n", pktcount,strtime(pcap_time.tv_sec),pcap_time.tv_usec, srcaddr, addrs.srcport, dstaddr, addrs.dstport);

  fprintf(f,"s %s\n", http_message->startline);

  for (i = 0; i < http_message->headers_count; i++)
    {
      fprintf(f,"h %s: %s\n", http_message->headers[i][0],http_message->headers[i][1]);
    }

  for (i = 0; i < http_message->cookies_count; i++)
    {
      fprintf(f,"c%d type=%s\n",i, http_message->cookies[i].set ? "SetCookie" : "Cookie");
      if (http_message->cookies[i].set)
        {
          if (http_message->cookies[i].expires)
            fprintf(f,"c%d expires='%s'\n", i, http_message->cookies[i].expires);
          if (http_message->cookies[i].path)
            fprintf(f,"c%d path='%s'\n", i,http_message->cookies[i].path);
          if (http_message->cookies[i].domain)
            fprintf(f,"c%d domain='%s'\n",i, http_message->cookies[i].domain);
        }
      for (j = 0; j < http_message->cookies[i].values_count; j++)
        {
          fprintf(f,"c%d name='%s' value='%s'\n",i,  http_message->cookies[i].values[j][0], http_message->cookies[i].values[j][1]);
        }
      for (k = 0; k < http_message->cookies[i].options_count; k++)
        fprintf(f,"c%d option='%s'\n", i, http_message->cookies[i].options[k]);
    }

  fprintf(f,"\n");

  fclose(f);

  snprintf(pathname, PATH_MAX, "%s/%s-%s.session", o.outdir, srcaddr, dstaddr);

  if ((f =  fopen(pathname, "a")) == NULL)
    FATAL("fopen(): %s", strerror(errno));

  if (strncasecmp(http_message->startline, "GET ", STATIC_STRLEN("GET ")) == 0 ||
      strncasecmp(http_message->startline, "POST ", STATIC_STRLEN("POST ")) == 0)
    {
      p = http_message->startline;
      if ((p = strchr(p, ' ')) != NULL && (q = strchr(++p, ' ')) != NULL)
        {
          *q = 0;
          if (*p == '/' && http_message->header_host)
            {
              fprintf(f,"%ld.%ld Link: http://%s%s\n", pcap_time.tv_sec,pcap_time.tv_usec, http_message->header_host, p);
//   LOG(1,1,"link: %s%s",  http_message->header_host, p);
            }
          else
            {
              if (*p != '/')
                {
                  fprintf(f,"%ld.%ld Link: %s\n", pcap_time.tv_sec,pcap_time.tv_usec, p);
//    LOG(1,1,"link: %s", p);
                }
            }

        }
    }

// format: "Set-Cookie: NAME=VALUE; expires=DATE; path=PATH; domain=DOMAIN_NAME"
  for (i = 0; i < http_message->cookies_count; i++) // each set of cookies...
    for (j = 0; j < http_message->cookies[i].values_count; j++)   // each cookie...
      {
        fprintf(f, "%ld.%ld Set-Cookie: %s=%s;", pcap_time.tv_sec,pcap_time.tv_usec, http_message->cookies[i].values[j][0],http_message->cookies[i].values[j][1]);

        if (!http_message->cookies[i].expires)
          {
            http_message->cookies[i].expires = HTTP_COOKIE_DEFAULT_EXPIRES;
          }

        if (!http_message->cookies[i].path)
          http_message->cookies[i].path = HTTP_COOKIE_DEFAULT_PATH;

        if ((!http_message->cookies[i].domain || *http_message->cookies[i].domain == 0) && http_message->header_host)
          {
            for (p=http_message->header_host;(q = strchr(p,'.')+1) && strchr(q,'.');p=q);
            http_message->cookies[i].domain= p;
            // Host = "Host" ":" host [ ":" port ] ; Section 3.2.2
            if ((q = strchr(p,':')))
              *q = 0;  // remove port if present
          }

        fprintf(f, " expires=%s;", http_message->cookies[i].expires);
        fprintf(f, " path=%s;", http_message->cookies[i].path);
        if (http_message->cookies[i].domain)
          fprintf(f, " domain=%s;",  http_message->cookies[i].domain);

        for (k = 0; k < http_message->cookies[i].options_count; k++)
          fprintf(f," %s;", http_message->cookies[i].options[k]);
        fprintf(f, "\n");
      }

  fclose(f);

  return 0;
}


// considera soltanto i pkt http "interessanti", non *tutti* i pacchetti http.
int seems_http_header(char *data, u_int32_t datalen)
{
  int32_t i, len, off;


// la funzione torna 1 se e' presente questo pattern all'inizio del payload:
// pattern1: reply '((HTTP/1.1\ )|(HTTP/1.0\ )).[0-9]'
// pattern2: request '(GET\ )|(POST\ )*[alnum]\ ((HTTP/1.1\ )|(HTTP/1.0\ ))'

  off = 0;
  len = datalen;

  if (strncasecmp(data, "HTTP/1.1 ",MIN(STATIC_STRLEN("HTTP/1.1 "),len)) == 0 ||
      strncasecmp(data, "HTTP/1.0 ",MIN(STATIC_STRLEN("HTTP/1.0 "),len)) == 0)
    {
      off+= STATIC_STRLEN("HTTP/1.1 ");
      len-= STATIC_STRLEN("HTTP/1.1 ");

      off ++;
      len --;
      if (len <= 0)
        return 0;

      if (data[off] < '0' || data[off] > '9')
        return 0;

      //    LOG(1,1,"HTTP reply RECOGNIZED");
      return 2;
    }

  if (strncasecmp(data, "GET ",MIN(STATIC_STRLEN("GET "),len)) == 0 ||
      strncasecmp(data, "POST ",MIN(STATIC_STRLEN("POST "),len)) == 0)
    {

      for (i = 0; data[off+i] != ' '; i++);
      i++;
      off += i;
      len -= i;
      if (len <= 0)
        return 0;

      for (i = 0; i < len && data[off+i] != ' '; i++);
      i++;
      off += i;
      len -= i;

      if (len <= 0)
        return 0;

      if (strncasecmp(data+off, "HTTP/1.1",MIN(STATIC_STRLEN("HTTP/1.1"),len)) == 0 ||
          strncasecmp(data+off, "HTTP/1.0",MIN(STATIC_STRLEN("HTTP/1.0"),len)) == 0)
        {
//          LOG(1,1,"HTTP request RECOGNIZED");
          return 1;
        }

      return 0;

    }

  return 0;
}


int parse_http_message(char *data, u_int32_t datalen, http_message_t *http_message)
{
  int32_t i,j,off,len;
  char *header_name = NULL, *header_value = NULL;
  static char buf[PCAP_SNAPLEN];


  if (datalen <= 0)
    return datalen;

  if (datalen >PCAP_SNAPLEN)
    FATAL("datalen > PCAP_SNAPLEN");

  memcpy(buf, data, datalen);

  memset(http_message, 0, sizeof(http_message_t));
  http_message->content_length = -1;


  off = 0;
  len = datalen;

  if ((i = parse_line(buf, len)) == -1)
    return -1;

  http_message->startline = buf;

  off+=i;
  len-=i;


  for (;;)
    {

      if (len <= 0)
        return -1;

      if ((i = parse_line(buf+off, len)) == -1)
        {
          // we are here if len<=0 but this never happens or if final \n not found (partial http message header)
          buf[off+len-1] = 0;
          for (j = len; j>=0 && buf[off+j] != ';';j--);
          if (j >= 0 )
            {
              buf[off+j] = 0;
            }
          else
            {
              buf[off] = 0;
            }
        }

      if (buf[off] == 0)
        {
          off+=i;
          len-=i;
          break;
        }

      parse_http_header(buf+off, &header_name, &header_value);

      off+=i;
      len-=i;


//        LOG(1,1,"http name '%s' value '%s'", header_name, header_value);

      if (strcasecmp(header_name, "Set-Cookie") == 0 ||
          strcasecmp(header_name, "Cookie") == 0)
        {
          // handling header as cookie ("Cookie:" or "Set-Cookie:")
          if (http_message->cookies_count >= HTTP_COOKIES_MAX)
            {
              LOG(1,1," * warning: too many http cookies in message!");
              continue;
            }
          if (parse_http_cookie(&http_message->cookies[http_message->cookies_count],*header_name == 's' || *header_name == 'S' ? 1 : 0, header_value) == -1)
            {
              LOG(1,1," * warning: pdrse_http_cookie failed!");
              continue;
            }
          http_message->cookies_count++;
        }
      else
        {
          if (strcasecmp(header_name, "Content-Length") == 0)
            {
              http_message->content_length = strtol((char *) header_value, (char **) NULL, 10);
              if (errno == ERANGE || http_message->content_length < 0)
                {
                  //LOG(1,1," * Content-Length is %ld", http_message->content_length );
                  return -1;
                }
            }
          if (strcasecmp(header_name, "Transfer-Encoding") == 0)
            {
              if (strcasecmp(header_value, "chunked") == 0)
                http_message->chunked_transfer_encoding = 1;
            }

          if (strcasecmp(header_name, "Host") == 0)
            {
              http_message->header_host = header_value;
              //LOG(1,1," * http_message_header_host: '%s'", http_message->header_host);
            }

          if (http_message->headers_count >= HTTP_HEADERS_MAX)
            {
              LOG(1,1," * warning: too many http headers in message!");
              continue;
            }
          http_message->headers[http_message->headers_count][0] = header_name;
          http_message->headers[http_message->headers_count][1] = header_value;
          http_message->headers_count++;
        }

    }

//  VLOG(1,1," * ok");

  return datalen-len;
}


void disable_nids_chksum()
{
  static struct nids_chksum_ctl ctl;


  ctl.netaddr = 0;
  ctl.mask = 0;
  ctl.action = NIDS_DONT_CHKSUM;
  nids_register_chksum_ctl(&ctl, 1);
}


int
main(int argc, char **argv)
{
  init_sighandlers();
  signal(SIGUSR2, sig_stats_handler);
  init_opt(argc, argv);

  if (o.mypcap_filter)
    add_pcap_filter(mypcap,o.mypcap_filter);

  nids_params.pcap_desc = mypcap;
  nids_params.scan_num_hosts = 0;
  nids_params.tcp_workarounds = 1;
  nids_params.syslog = syslog_libnids;
  nids_params.sk_buff_size = 200;

  if (!nids_init ())
    FATAL("nids_init(): %s", nids_errbuf);

  disable_nids_chksum();
  nids_register_tcp (tcp_callback);

  memset(&stats, 0, sizeof(stats));

  LOG(1,1," * You can dump stats sending me a SIGUSR2 signal");

  LOG(1,1," * Reading packets...");

  running = 1;

  loop(pcap_datalink(mypcap),o.dllength == -1 ? sizeof_datalink(mypcap) : o.dllength);

  raise(SIGTERM);
  return 0; // never reached
}


void
init_opt(int argc, char **argv)
{
  int             c;
  char pathname[PATH_MAX];


  o.mypcap_filter = NULL;
  o.rxfile = NULL;
  o.iface = NULL;
  o.dllength = -1;
  o.promisc = 0;
  o.outdir = strdup(DEFAULT_OUTDIR);
  o.stdout = 1;
  o.daemonize = 0;
  o.user =  NULL;
  o.verbose = 0;
  o.syslog = 0;
  o.savepcap = 0;
  o.handle1pkt= 1;

  if (argc ==1)
    help();

  opterr = 0;

  while ((c = getopt(argc, argv, "r:i:d:L:p:sZ:vDmFfh0")) != EOF)
    switch (c)
      {

      case '0':
        o.handle1pkt = 0;
        break;

      case 's':
        o.savepcap = 1;
        break;

      case 'r':
        SAFE_FREE(o.rxfile);
        o.rxfile = strdup(optarg);
        break;

      case 'i':
        SAFE_FREE(o.iface);
        o.iface =  strdup(optarg);
        break;

      case 'd':
        SAFE_FREE(o.outdir);
        o.outdir = strdup(optarg);
        break;

      case 'L':
        o.dllength = atoi(optarg);
        if (o.dllength <0)
          FATAL("dllength < 0");
        break;

      case 'p':
        o.mypcap_filter = strdup(optarg);
        break;


      case 'Z':
        SAFE_FREE(o.user);
        o.user = strdup(optarg);
        break;

      case 'v':
        o.verbose = 1;
        break;

      case 'D':
        o.daemonize = 1;
        break;

      case 'm':
        o.promisc = 1;
        break;

      case 'F':
        o.syslog = 1;
        break;

      case 'f':
        o.stdout = 0;
        break;

      case 'h':
        help();
        break;


      default:
        FATAL("option '%c' invalid", optopt);
      }

  if (o.daemonize)
    o.stdout = 0;

  if (o.stdout)
    enable_stdout();

  if (o.verbose)
    enable_verbose();

  get_next_name(o.outdir, "log.",".txt",&ndxlog) ;
  if (ndxlog == -1)
    FATAL("get_next_name(...): %s", strerror(errno));
  snprintf(pathname, PATH_MAX, "%s/log.%d.txt", o.outdir, ndxlog);
  open_logfile(pathname);

  if (o.syslog)
    enable_syslog();

  if (o.iface && o.rxfile)
    FATAL("dup packet source: -r or -i");

  if (!o.iface && !o.rxfile)
    FATAL("packet source required");

  if (o.rxfile)
    if ( (mypcap = pcap_open_offline(o.rxfile, errbuf)) == NULL)
      FATAL("pcap_open_offline(): %s", errbuf);

  if (o.iface)
    if ((mypcap = pcap_open_live(o.iface, PCAP_SNAPLEN, o.promisc, 0, errbuf)) == NULL)
      FATAL("pcap_open_live(): %s", errbuf);

  if (o.dllength == -1 && sizeof_datalink(mypcap) == -1)
    FATAL("sizeof_datalink == -1");

  if (o.savepcap)
    {
      snprintf(pathname, PATH_MAX, "%s/pkts.%d.pcap", o.outdir, ndxlog);
      if (exists(pathname))
        FATAL("pathname '%s' exists", pathname);
      if (!(pcap_dumper = pcap_dump_open(mypcap, pathname)))
        FATAL("pcap_dump_open(): %s", pcap_geterr(mypcap));
    }

  if (o.user)
    drop_privs(o.user, NULL); // group can be NULL, it's ok!

  if (o.daemonize)
    daemonize();

  LOG(1,1," + cookiesniffer of The Cookie Tools v%s running here!",VERSION);
  LOG(1,1," + pid: %d, date/time: %s",getpid(),strtime(time(NULL)));


  if (o.verbose)
    {
      LOG(1,0," + cmd: %s", argv[0]);
      for (c = 1; c < argc; c++)
        LOG(0,0," '%s'", argv[c]);
      LOG(0,1,"");
    }

  LOG(1,1," + Configuration");


  LOG(1,1,"   + INPUT");
  LOG(1,0,"     Packet source: ");

  if (o.rxfile)
    LOG(0,1,"rxfile '%s'", o.rxfile);
  else
    LOG(0,1,"iface '%s'", o.iface);

  LOG(1,0,"     Force datalink header length: ");
  if (o.dllength == -1)
    LOG(0,1,"disabled");
  else
    LOG(0,1,"%d bytes", o.dllength);

  LOG(1,1,"   + OUTPUT");

  LOG(1,1,"     Output directory: '%s'", o.outdir);

  LOG(1,1,"     Logfile: '%s/%d.txt'", o.outdir, ndxlog);

  LOG(1,0,"     Save pcap: ");
  if (o.savepcap)
    LOG(0,1,"'%s/pkts.%d.pcap'", o.outdir, ndxlog);
  else
    LOG(0,1,"disabled");

  LOG(1,1,"     stdout logging: %s",o.stdout ? "enabled" : "disabled");
  LOG(1,1,"     Syslog logging: %s",o.syslog ? "enabled" : "disabled");
  LOG(1,1,"     Be verbose: %s",o.verbose ? "enabled" : "disabled");

  LOG(1,1,"   + SELECT");
  LOG(1,1,"     Sniff in promiscuous mode: %s", o.promisc ?  "enabled" : "disabled");

  LOG(1,0,"     Add pcap filter: ");
  if (o.mypcap_filter)
    LOG(0,1,"'%s'", o.mypcap_filter);
  else
    LOG(0,1,"disabled");


  LOG(1,1,"   + EXECUTION");
  LOG(1,1,"     Running as user/group: %s/%s", getpwuid(getuid())->pw_name,getgrgid(getgid())->gr_name);
  LOG(1,1,"     Running daemonized: %s",  o.daemonize ? "enabled" : "disabled");

  LOG(1,1,"   + MISC");
  LOG(1,1,"     Single packet handling: %s", o.handle1pkt ? "enabled" : "disabled");
}


void help()
{
  printf("Copyright (c) 2007 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>\n");
  printf("cookiesniffer of the Cookie Tools v%s. The Cookie Tools are free software,\ncovered by the GNU General Public License version 2.\n\n", VERSION);

  printf("USAGE: cookiesniffer (-r|-i) <source> [options]\n");

  printf("\n INPUT\n\n");
  printf("  -r <str>      Read packets from file (pcap format) <str>\n");
  printf("  -i <str>      Read packets from network interface <str>\n");
  printf("  -L <int>      Force datalink header length == <int>\n");
  printf("\n OUTPUT\n\n");
  printf("  -d <str>      Set output directory to <str> (def: '%s')\n",DEFAULT_OUTDIR);
  printf("  -s            Save packets to 'x/pkts.y.pcap'\n");
  printf("  -f            Disable stdout logging\n");
  printf("  -F            Enable syslog logging\n");
  printf("  -v            Be verbose\n");
  printf("\n SELECT\n\n");
  printf("  -m            Sniff in promiscuous mode\n");
  printf("  -p <str>      Add pcap filter <str>\n");
  printf("\n EXECUTION\n\n");
  printf("  -Z <str>      Run as user <str>\n");
  printf("  -D            Run in background (option -f implicit)\n");
  printf("\n MISC\n\n");
  printf("  -0            Disable single packet handling (may cause information loss)\n");
  printf("  -h            This\n");
  printf("\n");

  exit(0);
}


void cleanup()
{
  if (running)
    raise(SIGUSR2); // show state...

  SAFE_PCAP_CLOSE(mypcap);
  SAFE_FREE(o.rxfile);
  SAFE_FREE(o.iface);
  SAFE_FREE(o.user);
  SAFE_FREE(o.outdir);
  SAFE_FREE(o.mypcap_filter);
  SAFE_PDCLOSE(pcap_dumper);
}


void sig_stats_handler(int signo)
{
  LOG(1,1," + Status");
  LOG(1,1,"   Network Packets: %d",pktcount);
  LOG(1,1,"   Active HTTP Connections: %d", stats.http_conns_active_count);
  LOG(1,1,"   Closed HTTP Connections: %d", stats.http_conns_closed_count);
  LOG(1,1,"   Detected HTTP Connections: %d", stats.http_conns_active_count + stats.http_conns_closed_count);
  LOG(1,1,"   Saved Cookies: %d", stats.cookies_count);
  LOG(1,1,"   Sync HTTP Connections: %d", stats.http_conns_sync_count);
  LOG(1,1,"   Desync HTTP Connections: %d", stats.http_conns_desync_count);
  LOG(1,1,"   Resync HTTP Connections: %d", stats.http_conns_resync_count);
}


int inject_tcp_open3way(struct pcap_pkt *ppkt)
{
  struct libnet_ipv4_hdr *pktip;
  struct libnet_tcp_hdr *pkttcp;


  pktip = (struct libnet_ipv4_hdr *)(ppkt->pkt + ppkt->dllength);
  pkttcp = (struct libnet_tcp_hdr *)(ppkt->pkt + ppkt->dllength+(pktip->ip_hl << 2));

//  LOG(1,1,"injecting packets...");

  inject_tcp_pkt(ppkt,pktip->ip_src.s_addr,
                 pktip->ip_dst.s_addr,
                 pkttcp->th_sport,
                 pkttcp->th_dport,
                 htonl(ntohl(pkttcp->th_seq)-1),
                 0,
                 TH_SYN);

  inject_tcp_pkt(ppkt,pktip->ip_dst.s_addr,
                 pktip->ip_src.s_addr,
                 pkttcp->th_dport,
                 pkttcp->th_sport,
                 htonl(ntohl(pkttcp->th_ack)-1),
                 pkttcp->th_seq,
                 TH_SYN|TH_ACK);

  inject_tcp_pkt(ppkt,pktip->ip_src.s_addr,
                 pktip->ip_dst.s_addr,
                 pkttcp->th_sport,
                 pkttcp->th_dport,
                 pkttcp->th_seq,
                 pkttcp->th_ack,
                 TH_ACK);

  return 0;
}


int
inject_tcp_pkt(struct pcap_pkt *ppkt, u_int32_t ip_src, u_int32_t ip_dst,u_int16_t port_src, u_int16_t port_dst, u_int32_t tcp_seq, u_int32_t tcp_ack, u_int8_t tcp_flags)
{
  static    u_int8_t        *buf = NULL;
  struct libnet_ipv4_hdr *pkt_ip;
  struct libnet_tcp_hdr *pkt_tcp;
  struct pcap_pkthdr header;
  addrs_t addrs;


  if (buf == NULL)
    buf = alloca(ppkt->dllength + LIBNET_IPV4_H + LIBNET_TCP_H);

// il pacchetto ha dimensione fissa  datalink_header_length + LIBNET_IPV4_H + LIBNET_TCP_H
  header.ts = ppkt->hdr.ts;
  header.caplen= ppkt->dllength + LIBNET_IPV4_H + LIBNET_TCP_H;
  header.len= ppkt->dllength + LIBNET_IPV4_H + LIBNET_TCP_H;

  pkt_ip = (struct libnet_ipv4_hdr *) ((u_int8_t *) buf + ppkt->dllength);
  pkt_tcp = (struct libnet_tcp_hdr *) ((u_int8_t *) pkt_ip +
                                       LIBNET_IPV4_H);

  memcpy(buf, ppkt->pkt, ppkt->dllength);

  pkt_ip->ip_v = IPVERSION;
  pkt_ip->ip_hl = LIBNET_IPV4_H / 4;  // 20/4 = 5
  pkt_ip->ip_tos = 0;
  pkt_ip->ip_len = htons(LIBNET_IPV4_H + LIBNET_TCP_H);
  pkt_ip->ip_id = 0;          // linux sets this to 0
  pkt_ip->ip_off = htons(IP_DF);
  pkt_ip->ip_ttl = 64;
  pkt_ip->ip_p = IPPROTO_TCP;
  pkt_ip->ip_sum = 0;         // kernel fills it
  pkt_ip->ip_src.s_addr = ip_src;
  pkt_ip->ip_dst.s_addr = ip_dst;

  pkt_tcp->th_sport = port_src;
  pkt_tcp->th_dport = port_dst;
  pkt_tcp->th_seq = tcp_seq;
  pkt_tcp->th_ack = tcp_ack;

  pkt_tcp->th_x2 = 0;
  pkt_tcp->th_off = LIBNET_TCP_H / 4; // 20/4 = 5

  pkt_tcp->th_flags = tcp_flags;

  pkt_tcp->th_win = 100;
  pkt_tcp->th_sum = 0;
  pkt_tcp->th_urp = 0;

  addrs.srcaddr = pkt_ip->ip_src.s_addr;
  addrs.dstaddr = pkt_ip->ip_dst.s_addr;
  addrs.srcport = ntohs(pkt_tcp->th_sport);
  addrs.dstport = ntohs(pkt_tcp->th_dport);

//   VLOG(1,0," * injecting tcp packet from %s:%d to ",INET_NTOA(addrs.srcaddr),addrs.srcport);
//   VLOG(0,1,"%s:%d",INET_NTOA(addrs.dstaddr),addrs.dstport);

  nids_pcap_handler(0,&header, buf);

  if (pcap_dumper)
    pcap_dump((u_int8_t *) pcap_dumper, &header, buf);

  return 0;
}


/* EOF */

