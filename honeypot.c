#include "honeypot.h"

int start_ap(lorcon_t *context, lorcon_packet_t *packet) {
	printd(HP_INFO, "Starting AP.");
}


/*int get_probe_ssid(lorcon_packet_t *packet, char **result) {
	char ssid[HP_SSID_MAX_LEN];
	int i;

	if((packet->packet_header[HP_80211_P_SSID_LEN] != 0) && (packet->packet_header[HP_80211_P_SSID_LEN] < 255)) {
		for(i=0; i<packet->packet_header[HP_80211_P_SSID_LEN]; i++) {
			ssid[i] = packet->packet_header[HP_80211_P_SSID + i];
		}

		*result = strdup(ssid);
	} else {
		return -1;
	}
}*/

/* 	Ensure the SSID > 0 && < 255 before parsing to determine
	it's the frame we're after. If so populate VAP info */
int parse_probe_request(lorcon_packet_t *packet) {
	char ssid[HP_MAC_LEN];
	char mac[HP_MAC_LEN];
	int ret, i;
	int pssidLen;

	mac[HP_MAC_LEN] = '\0';

	if((packet->packet_header[HP_80211_P_SSID_LEN] != 0) && (packet->packet_header[HP_80211_P_SSID_LEN] < 255)) {
		for(i=0; i<packet->packet_header[HP_80211_P_SSID_LEN]; i++) {
			ssid[i] = packet->packet_header[HP_80211_P_SSID + i];
		}

		ssid[packet->packet_header[HP_80211_P_SSID_LEN]] = '\0';

		printd(HP_INFO, "[probe] %s", ssid);

		if(strcmp(ap_info.ssid, ssid) == 0) {
			ap_info.valid_probe = 1;
			return 1;
		}
	}

	return -1;
}

void packet_handler(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {
	uint8_t packetType = packet->packet_header[HP_80211_TYPE];

	switch(packetType) {
		case HP_80211_PROBE_REQ_FRAME:
			if(parse_probe_request(packet) && ap_info.ap_created == 0 && ap_info.valid_probe == 1) {
				ap_info.valid_probe = 0;
				if(start_ap(context, packet) == 0)
					ap_info.ap_created = 1;
			}

			break;
	}
}
