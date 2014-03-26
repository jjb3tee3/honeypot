#include "honeypot.h"

void packet_handler(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {
	uint8_t packetType = packet->packet_header[HP_80211_TYPE];

	switch(packetType) {
		case HP_80211_PROBE_REQ_FRAME:
			printd(HP_DEBUG, "Probe request.");
			break;
	}
}
