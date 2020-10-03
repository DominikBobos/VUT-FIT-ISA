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
// #include <time.h>				//						//
// #include <sys/types.h>			//////////////////////////
// #include <netdb.h>				//////////////////////////
// #include <arpa/inet.h>			//						//
// #include <pcap.h>				//						//
// #include <netinet/ip.h>			// Libs for sniffing 	//
// #include <netinet/tcp.h>		//						//
// #include <netinet/udp.h>		//						//
// #include <netinet/if_ether.h>	//						//
// #include <netinet/ip6.h> 		//////////////////////////


int args_parse(int argc, char *argv[], char *iface, char *rfile)
{
	bool iface_bool = false;
	bool rfile_bool = false;
	static const struct option longopts[] = 
	{
		{.name = "help", .has_arg = no_argument, .val = 'h'},
	};
	for (;;) 
	{
		int opt = getopt_long(argc, argv, "i:r:h", longopts, NULL);
		if (opt == -1){
			break; 
		}
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 20)			
			{
				fprintf(stderr, "Parameter for INTERFACE could not be longer than 20 characters!\n");
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
			puts("HELP:");
			puts("-i <interface> interface, on which SSL connection monitor works");
			puts("-r <file> pcapng file to read SSL connection from ");
			return 0;
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
	if (args == 1) {
		free(iface);
		free(rfile);
		return 1;		// when something went wrong
	}
	printf("interface=%s, pcapng file=%s\n", iface, rfile);

	free(iface);
	free(rfile);
}