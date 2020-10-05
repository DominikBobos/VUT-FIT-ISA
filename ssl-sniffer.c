/*******************************************
	NAME:			
	DESCRIPTION:	
	AUTHOR:			Dominik Boboš (xbobos00)
	AC.YEAR:		2020/2021
********************************************/


#include <stdio.h>				//////////////////////////
#include <signal.h>				//						//
#include <stdlib.h> 			//						//
#include <stdbool.h>			//						//
#include <ctype.h>				//	C-dependencies		//
#include <string.h>				//						//
#include <getopt.h>				//						//
#include <time.h>				//						//
#include <sys/types.h>			//////////////////////////
#include <netdb.h>				//////////////////////////
#include <arpa/inet.h>			//						//
#include <pcap.h>				//						// sudo apt-get install libpcap0.8-dev
#include <netinet/ip.h>			// Libs for sniffing 	//
#include <netinet/tcp.h>		//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h> 		//////////////////////////


int show_interfaces() 
{
	char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	pcap_if_t *alldevs, *dlist;
	int i = 0;
	  // Shows list of the all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	// Print the list to user
	//  MODIFICATED from
	// source: https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
	// author: HIMANSHU ARORA
	// date: 25th OCTOBER, 2012
	printf("\nAll available interfaces to listen:\n");
	for(dlist=alldevs; dlist; dlist=dlist->next)
	{
		printf("\t%d. %s", ++i, dlist->name);
		if (dlist->description)
			printf(" (%s)\n", dlist->description);
		else
			printf("(No description)\n");
	}
	return 0;
}


int print_help() 
{
	puts("HELP:");
	puts("-i <interface> interface, where the SSL monitor captures the connection");
	puts("-r <file> pcapng file to get SSL connection from ");
	return 0;
}

int args_parse(int argc, char *argv[], char *iface, char *rfile)
{
	bool iface_bool = false;
	bool rfile_bool = false;
	static const struct option longopts[] = 
	{
		{.name = "help", .has_arg = no_argument, .val = 'h'},
	};
	int i = 0;
	for (;;) 
	{
		int opt = getopt_long(argc, argv, "i:r:h", longopts, NULL);
		if (opt == -1 && i == 0){
			print_help();
			show_interfaces();
			return 0;
		}
		i++;
		if (opt == -1) {
			break;
		}
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 20)			
			{
				fprintf(stderr, "Parameter for interface could not be longer than 20 characters!\n");
				return 1;
			}
			strcpy(iface, optarg);
			iface_bool = true;
			break;
		case 'r':
			if (strlen(optarg) > 200)				
			{
				fprintf(stderr, "Parameter for pcapng file could not be longer than 200 characters!\n");
				return 1;
			}
			strcpy(rfile, optarg);
			rfile_bool = true;
			break;
		case 'h':
		default:
			print_help();
		}
	}
	if (iface_bool == false ){	// -i interface was not specified
		return 10;
	}
	if (rfile_bool == false ){	// -r pcapng file was not specified
		return 20;
	}
	return 30;					// both -r and -i was entered
}


int main(int argc, char *argv[])
{
	char *iface = malloc(21 * sizeof(char));	//interface
	char *rfile = malloc(201 * sizeof(char));		//pcapng file
	if (iface == NULL) { return 1; }
	if (rfile == NULL) { return 1; }

	int args = args_parse(argc, argv, iface, rfile);
	if (args == 1 || args == 0) {
		free(iface);
		free(rfile);
		return args == 1 ? 1 : 0;		// when something went wrong (1) or help was asked (0)
	}
	if (args == 20 || args == 30) {		// we're using live capture from interface
		if (args == 30) {
			printf("Both arguments were used. Not reading from pcapng file. Only listening from interface: %s.\n", iface);
		}
		free(rfile);
		rfile = NULL;
	}
	if (args == 10) {
		free(iface);	// we're using pcapng file
		iface = NULL;
	}

	// printf("interface=%s, pcapng file=%s\n", iface, rfile);


	if (args != 10) {
		free(iface);
	}
	else {
		free(rfile);
	}
	return 0;
}