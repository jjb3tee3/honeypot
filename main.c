#include "honeypot.h"

ap_info_t ap_info;

void printd(unsigned int level, const char* format, ...) {
	va_list arg;

	switch(level) {
		case HP_DEBUG:
			printf("[*] ");
			break;
		case HP_INFO:
			printf("[-] ");
			break;
		case HP_ERROR:
			printf("[!] ");
			break;
		default:
			printf("[-] ");
	}

	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);
	printf("\n");
}

void sig_handler(int signo) {
	printf("exiting app.");
	exit(0);
}

void init_VAP() {
	ap_info.bssid = HP_VAP_BSSID;
	ap_info.src_mac = HP_VAP_SRC_MAC;
	ap_info.ssid = NULL;
	ap_info.recv_probe_request = 0;
	ap_info.ap_created = 0;
}

void usage() {

}

int parse_cmdline_args(char **iface, int argc, char **argv) {
	int c;

	while((c = getopt(argc, argv, "i:s:hc:b:")) != EOF) {
		switch(c) {
			case 'i':
				*iface = strdup(optarg);
				break;
			case 's':
				if(strlen(strdup(optarg)) < 255) {
					ap_info.ssid = strdup(optarg);
					ap_info.ssid_len = strlen(ap_info.ssid);
				} else {
					printd(HP_ERROR, "SSID length > 255");
					return -1;
				}
				break;
			case 'c':
				ap_info.channel = atoi(optarg);
				break;
			case 'h':
				usage();
				break;
			default:
				usage();
				break;
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	char *iface;
	int ret;
	
	lorcon_t *context;
	lorcon_driver_t *dlist, *driver;

	init_VAP();
	parse_cmdline_args(&iface, argc, argv);

	printd(HP_INFO, "Interface: \"%s\"", iface);
	printd(HP_INFO, "SSID: \"%s\"", ap_info.ssid);
	printd(HP_INFO, "Channel: %d", ap_info.channel);
	
	signal(SIGINT, sig_handler);

	if((driver = lorcon_auto_driver(iface)) == NULL) {
		printd(HP_ERROR, "Could not detect driver for %s", iface);
		return -1;
	} else {
		printd(HP_ERROR, "Driver: \"%s\"", driver->name);
	}

	if((context = lorcon_create(iface, driver)) == NULL) {
		printd(HP_ERROR, "Failed to create context");
		return -1;
	}

	if(lorcon_open_injmon(context) < 0) {
		printd(HP_ERROR, "Could not create injection/monitor mode interfce.");
		lorcon_free_driver_list(driver);
	}	

	lorcon_set_channel(context, ap_info.channel);
	lorcon_loop(context, 0, packet_handler, NULL);
	lorcon_close(context);
	lorcon_free(context);

	return 0;
	
}
