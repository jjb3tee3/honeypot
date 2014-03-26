#ifndef _HONEY_POT_H_
#define _HONEY_POT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>

#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packasm.h>

#include <sys/socket.h> /* Possibly for TCP integration */
#include <netinet/in.h> /* Possibly for TCP integration */


#define HP_DEBUG		0
#define HP_INFO			1
#define HP_ERROR		2

#define HP_DEBUG_PREFIX 	"[*]"
#define HP_INFO_PREFIX		"[-]"
#define HP_ERROR_PREFIX		"[!]"

#define HP_MAC_LEN		6
#define HP_SSID_MAX_LEN 256

/* 802.11 field positions */
#define HP_80211_SRC_MAC	9
#define HP_80211_DST_MAC	3
#define HP_80211_BSSID		15
#define HP_80211_SSID_LEN	37
#define HP_80211_SSID		38
#define HP_80211_P_SSID		26
#define HP_80211_P_SSID_LEN	25
#define HP_80211_P_SRC		10
#define HP_80211_TYPE		0

/* Frame types */
#define HP_80211_PROBE_REQ_FRAME	0x40
#define HP_80211_PROBE_RESP_FRAME	0x50
#define HP_80211_AUTH_FRAME			0xB0
#define HP_80211_ASSOC_REQ_FRAME	0x00
#define HP_80211_ASSOC_RESP_FRAME	0x01

#define HP_VAP_SRC_MAC 	"\x00\x00\xDE\xAD\xBE\xEF"
#define HP_VAP_BSSID 	"\x00\x00\xDE\xAD\xBE\xEF"

struct AP_INFO {
	char *ssid;
	uint8_t ssid_len;

	uint8_t *bssid;

	uint8_t channel;

	uint8_t *src_mac;
	uint8_t *dst_mac;

	int recv_probe_request;
	int valid_probe;
	int ap_created;
};

typedef struct AP_INFO ap_info_t;

ap_info_t ap_info;

/* Should probably go in a seperate header */
void printd(unsigned int, const char*, ...);
void sig_handler(int);

void init_VAP();
void usage();
int parse_cmline_args(char **, int, char **);

void packet_handler(lorcon_t *, lorcon_packet_t *, u_char *);
#endif
