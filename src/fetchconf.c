/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id: conf.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire, Technologies Coeus inc.
 */

#define _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "fetchconf.h"



int level = 0;

typedef enum {
	oBadOption,
	oClientTimeout,
	oCheckInterval,
	oAuthInterval,
	oHTTPDMaxConn,
	oTrustedMACList,
	oFirewallRule,
} OpCodes;


static const struct {
	const char *name;
	OpCodes opcode;
} confwords[] = {
	{ "clienttimeout",      	oClientTimeout },
	{ "checkinterval",      	oCheckInterval },
	{ "authinterval",      	oAuthInterval },
	{ "httpdmaxconn",       	oHTTPDMaxConn },
	{ "trustedmaclist",		oTrustedMACList },
	{ "firewallrule",		oFirewallRule },
	{ NULL,				oBadOption },
};

static OpCodes conf_parse_line(const char *line,int paramnum);
static void conf_read(const char *line, s_config	*config);
void parse_trust_mac_list(char *ptr,s_config	*config);
void parse_allow_rules(char *ptr,s_config	*config);

static OpCodes
conf_parse_line(const char *line,int paramnum)
{
	int i;

	for (i = 0; confwords[i].name; i++)
		if (strcasecmp(line, confwords[i].name) == 0)
			return confwords[i].opcode;

	debug(LOG_ERR, "%s: line %d ", line, paramnum);
	
	return oBadOption;
}


#define TO_NEXT_CONF(s, e) do { \
	while (*s != '\0' && *s != '&') { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
	} else { \
		e = 1; \
	} \
} while (0)

void parse_trust_mac_list(char *ptr,s_config	*config) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	char *p1;
	t_trusted_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);
	
	if ((p1 = strchr(ptrcopy, '&'))) {
			p1[0] = '\0';
	} 
	

	while ((possiblemac = strsep(&ptrcopy, "+ "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

			if (config->trustedmaclist == NULL) {
				config->trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
				config->trustedmaclist->mac = safe_strdup(mac);
				config->trustedmaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config->trustedmaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_trusted_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}

void parse_allow_rules(char *ptr,s_config	*config) {
	char *ptrcopy = NULL;
	char *possibleip = NULL;
	char *publicip = NULL;
  t_firewall_target target = TARGET_ACCEPT;
	char *p1;
	t_firewall_ruleset *tmpr;
	t_firewall_ruleset *tmpr2;
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;
	
	debug(LOG_DEBUG, "Parsing string [%s] for trusted IP addresses", ptr);

	publicip = safe_malloc(16);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);
		if ((p1 = strchr(ptrcopy, '&'))) {
			p1[0] = '\0';
	} 
	
	
	
	
	while ((possibleip = strsep(&ptrcopy, "+ "))) {
		
		if (sscanf(possibleip, " %15[0-9.]", publicip) == 1) {
			/* Copy mac to the list */
			
			debug(LOG_DEBUG, "Adding IP address [%s] to trusted list", publicip);


		
			tmp = safe_malloc(sizeof(t_firewall_rule));
			memset((void *)tmp, 0, sizeof(t_firewall_rule));
			tmp->target = target;
			tmp->mask = safe_strdup(publicip);
			
				/* Append the rule record */
			if (config->rulesets == NULL) {
				config->rulesets = safe_malloc(sizeof(t_firewall_ruleset));
				memset(config->rulesets, 0, sizeof(t_firewall_ruleset));
				config->rulesets->name = safe_strdup("global");
				tmpr=config->rulesets;
			} else {
				tmpr2 = tmpr = config->rulesets;
				while (tmpr != NULL && (strcmp(tmpr->name, "global") != 0)) {
					tmpr2 = tmpr;
					tmpr = tmpr->next;
				}
				if (tmpr == NULL) {
					/* Rule did not exist */
					tmpr = safe_malloc(sizeof(t_firewall_ruleset));
					memset(tmpr, 0, sizeof(t_firewall_ruleset));
					tmpr->name = safe_strdup("global");
					tmpr2->next = tmpr;
				}
			}
		
			/* At this point, tmpr == current ruleset */
			if (tmpr->rules == NULL) {
				/* No rules... */
				tmpr->rules = tmp;
			} else {
				tmp2 = tmpr->rules;
				while (tmp2->next != NULL)
					tmp2 = tmp2->next;
				tmp2->next = tmp;
			}

		}
	}

	free(ptrcopy);

	free(publicip);

}



void
conf_read(const char *line,s_config	*config)
{
	char *s, *p1;
	int opcode, value,finished=0,paramnum=0;
	int linenum = strlen(line);
	
	if(linenum==0){
		return;
	}
	
	debug(LOG_DEBUG, "linunum:",linenum);
	s = line;
	while (finished==0) {
		paramnum++;
		debug(LOG_DEBUG, "begin parse %d",paramnum);
		
		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, '='))) {
			p1[0] = '\0';
		} 
		
		if (p1) {
			p1++;
		}

		if (p1 && p1[0] != '\0') {

			opcode = conf_parse_line(s,paramnum);

			switch(opcode) {
			case oHTTPDMaxConn:
				sscanf(p1, "%d", &(config->httpdmaxconn));
				debug(LOG_DEBUG, "HTTPDMaxConn");
				break;
			case oCheckInterval:
				sscanf(p1, "%d", &(config->checkinterval));
				debug(LOG_DEBUG, "oCheckInterval");
				break;
			case oAuthInterval:
				sscanf(p1, "%d", &(config->authinterval));
				debug(LOG_DEBUG, "oAuthInterval");
				break;
			case oClientTimeout:
				sscanf(p1, "%d", &(config->clienttimeout));
				debug(LOG_DEBUG, "oClientTimeout");
				break;
			case oTrustedMACList:
				parse_trust_mac_list(p1,config);
				break;
			case oFirewallRule:
				parse_allow_rules(p1,config);
				break;
			case oBadOption:
				debug(LOG_DEBUG, "oBadOption");
				break;

			}
			debug(LOG_DEBUG, "this word %s %d",s,finished);
			s = p1;
			TO_NEXT_CONF(s, finished);
			debug(LOG_DEBUG, "next word %s %d",s,finished);
			
		}
	}

}

void
fetchconf(s_config	*config)
{
        ssize_t			numbytes;
        size_t	        	totalbytes;
	int		sockfd, nfds, done;

	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	FILE * fh;
	
	char  *str = NULL;
	int interval;
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		level = 1;
		return;
		
	}

	/*
	 * Prep & send request
	 */
	snprintf(request, sizeof(request) - 1,
			"GET %sfetchconf/?gw_id=%s HTTP/1.0\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			auth_server->authserv_path,
			config_get_config()->gw_id,
			VERSION,
			auth_server->authserv_hostname);

	
	send(sockfd, request, strlen(request), 0);

	debug(LOG_DEBUG, "Reading response %s %s",auth_server->authserv_path,auth_server->authserv_hostname);
	
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';
	
	
	
	
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);
	
   str = strstr(request, "Conf:");
   str =str+5;
   
		if(str){	
			debug(LOG_DEBUG, "config %s", str);
			conf_read(str,config);
			;
			debug(LOG_DEBUG, "Auth Server Says OK" );	
		}					
	

	
	return;	
}
