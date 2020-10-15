/*******************************************
	NAME:			SSL connection monitor
	DESCRIPTION:	Catch SSLv2 to TLSv1.2 connection and outputs info about it
	AUTHOR:			Dominik Boboš (xbobos00)
	AC.YEAR:		2020/2021
********************************************/


#include "ssl-monitor.h"        // My own header file   //
#include <stdio.h>				//////////////////////////
#include <signal.h>				//						//
#include <stdlib.h> 			//						//
#include <stdbool.h>			//	C-dependencies		//
#include <string.h>				//						//
#include <getopt.h>				//						//
#include <time.h>				//						//
#include <sys/types.h>			//////////////////////////
#include <netdb.h>				//////////////////////////
#include <arpa/inet.h>			//						//
#include <pcap.h>				//						//
#include <netinet/ip.h>			// Libs for parsing 	//
#include <netinet/tcp.h>		//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h> 		//////////////////////////
//Tested with libpcap0.8 to install use this -> sudo apt-get install libpcap0.8-dev


tDLList connection_list; //list to track SSL/TLS connections

/*
 * Show all available devices to listen
 * returns 0 on success
 */
int show_interfaces()
{
	char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	pcap_if_t *alldevs, *dlist;
	int i = 0;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // Shows list of the all devices
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -5;
	}
	// Print the list to user
	// MODIFICATED from:
	// source: https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
	// author: HIMANSHU ARORA
	// date: 25th OCTOBER, 2012
    printf("\nAll available interfaces to listen:\n");
    for (dlist = alldevs; dlist; dlist = dlist->next) {
        printf("\t%d. %s", ++i, dlist->name);
        if (dlist->description) {
            printf(" (%s)\n", dlist->description);
        }
        else {
            printf("(No description)\n");
        }
    }
	return 0;
}

/*
 *	Function to properly catch keyboard interruptions
*/
void intHandler()
{
    DLDisposeList(&connection_list);
    printf("Keyboard interrupt detected. Terminating the SSL Monitor.\n");
    exit(0);
}


/*
 * Prints help to standard output
 */
void print_help()
{
    printf("\t\t\t----------------------\n\t\t\tSSL connection monitor\n\t\t\t----------------------\n"
           "The program catch SSL connection from SSlv2 to TLS1.2 version\n\n"
           "OUTPUT FORMAT:\n\t<timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>\n");
	puts("USAGE:\n"
      "\t-i [<interface name>|<interface number>] interface, where the SSL monitor captures the connection\n"
      "\t-r <file> pcap/pcapng file to get SSL connection from \n"
      "\nIf the program does not work. Launch it with sudo.\n"
      "When both -i and -r are selected, only -i is in use.\n"
      "Use no arguments to show available devices to listen.");
}


/*
 * Function for parsing command line arguments.
 * Takes int argc and char **argv, and char * to interface and pcapng file
 * returns 0 when printing help
 * returns 10 when -r was used
 * returns 20 when -i was used
 * returns 30 when both -i and -r were used
 * returns 1 on error
 */
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
			if (strlen(optarg) > 40) {
				fprintf(stderr, "Parameter for interface could not be longer than 40 characters!\n");
				return 1;
			}
			strcpy(iface, optarg);
			iface_bool = true;
			break;
		case 'r':
			if (strlen(optarg) > 200) {
				fprintf(stderr, "Parameter for pcapng file could not be longer than 200 characters!\n");
				return 1;
			}
			strcpy(rfile, optarg);
			rfile_bool = true;
			break;
		case 'h':
		default:
			print_help();
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


/*
 * Prints the whole SSL connection to STDOUT
 * Takes uint16_t src_port - source port, dst_port - destination port
 * the info about the connection is in the tDLList connection_list;
 */
void print_data(uint16_t src_port, uint16_t dst_port, char *src_addr, char *dst_addr)
{

    for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)) {
        if ((connection_list.Act->port == ntohs(src_port) &&
        (strcmp(connection_list.Act->data.src_addr, src_addr) == 0 || strcmp(connection_list.Act->data.src_addr, dst_addr) == 0)) ||
        (connection_list.Act->port == ntohs(dst_port) &&
        (strcmp(connection_list.Act->data.src_addr, src_addr) == 0 || strcmp(connection_list.Act->data.src_addr, dst_addr) == 0))) {
            long duration_sec = connection_list.Act->data.end_time - connection_list.Act->data.start_time;
            long duration_usec = connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
            if (duration_usec < 0) {
                duration_usec = 1000000 + connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
                duration_sec -= 1; //i use the second for micro seconds
            }
            char datetime[50];
            strftime(datetime,sizeof(datetime),"%Y-%m-%d %H:%M:%S", localtime(&connection_list.Act->data.start_time));
            printf("%s.%06ld,%s,%u,%s,%s,%d,%d,%ld.%06ld\n", datetime, connection_list.Act->data.start_microsec,
                   connection_list.Act->data.src_addr,connection_list.Act->data.src_port,connection_list.Act->data.dest_addr,
                   connection_list.Act->data.sni,connection_list.Act->data.size ,connection_list.Act->data.packets, duration_sec, duration_usec);
            if (connection_list.First == connection_list.Act) {
                DLDeleteFirst(&connection_list);
            } else {
                DLPred(&connection_list);
                DLPostDelete(&connection_list);
            }
            break;
        }
    }
}



/*
 * returns IPv4 address in a readable form
*/
char *readIPv4(struct in_addr ip_addr)
{
    char *ip = malloc(NI_MAXHOST * sizeof(char));	//buffer about size of the max host
    if (!ip)
    {	return NULL;}
    strcpy(ip, inet_ntoa(ip_addr));	//converts to readable address
    if (ip == NULL)
    {
        perror("inet_ntoa");
        return NULL;
    }
    return ip;
}


/*
 * returns IPv6 address in a readable form
*/
char *readIPv6(struct in6_addr ip_addr)
{
    char *ip = malloc(NI_MAXHOST * sizeof(char));	//INET6_ADDRSTRLEN
    if (!ip)
    {	return NULL;}
    if (inet_ntop(AF_INET6, &ip_addr, ip, NI_MAXHOST) == NULL)	//converts to readable address
    {
        perror("inet_ntop");
        return NULL;
    }
    return ip;
}

/*
 * Gets SNI from SSL packet of type Client-Hello
 * returns NULL on fail
 * returns char *SNI on success
 */
char *get_TLS_SNI(const u_char *buffer, int tcphdr_len)
{
    int x =  *(int_least8_t *)(&buffer[tcphdr_len + 43]);                   //session ID length
    int y = ntohs(*(uint32_t *)(&buffer[tcphdr_len + 43 + x + 1])); // cipher suites length
    int pos = tcphdr_len + 43 + x + 1 + y ;                                 // position in byte array
    int extenstion_length = ntohs(*(uint32_t *)(&buffer[pos + 4]));
    int length = 0;                                                         // server name length
    for (int i = 6; i < extenstion_length;){
        if (ntohs(*(uint32_t *)(&buffer[pos + i])) == 0) {          // type server name (0x0000 == 0)
            length = ntohs(*(uint32_t *)(&buffer[pos + i + 7]));    //server name length
            pos = pos + i + 9;                                              //updates position - place where SNI is
            break;
        }
        else {
            i += 2;
            i += ntohs(*(uint32_t *)(&buffer[pos + i])) + 2 ;
        }
    }
    if (length < 1) { return NULL; }    // 0 length of SNI (to prevent malloc fail)
    char *SNI = malloc(length+1 * sizeof(char));    // +1 because of '\0'
    if (!SNI) {	return NULL; }                           // malloc fail
    for(int i = 0; i < length; i++){
        SNI[i] = (char)(buffer[pos + i]);
    }
    SNI[length] = '\0';
    return SNI;
}


/*
 * returns the real length of payload if there is
 * more TLS packets sticked together in one TCP connection
 * returns 0 if there are no more occurences of TLS packets.
 * otherwise it returns the length in the found header
 */
int loop_packet (const u_char *buffer, int tcphdr_len, unsigned int data_len, int *last_found, int *first_found) {
    int payload_size = 0;
    tcphdr_len += 3;    //offset used for to not count the payload we have already counted (jumps 3 bytes in buffer)
    bool first = true;
    for(int i = 0; i < (int)data_len; i++) {
        if (((buffer[tcphdr_len + i] == 0x14) ||    //checks the buffer for another TLS packet in payload
             (buffer[tcphdr_len + i] == 0x15) ||
             (buffer[tcphdr_len + i] == 0x16) ||
             (buffer[tcphdr_len + i] == 0x17)) &&
            (buffer[tcphdr_len + 1 + i] == 0x03 && (buffer[tcphdr_len + 2 + i] < 0x04))) {
            uint32_t length = *(uint32_t *)(&buffer[tcphdr_len + i + 3]);
            payload_size += ntohs(length);
            if (first && first_found != NULL) {
                *first_found = ntohs(length);
                first = false;
            }
            *last_found = ntohs(length);
        }
    }

    return payload_size;
}

/*
 *  Function parses the SSL header and saves the info to the pckt_info header
 *  all the pckt_info variables are saved in connection_list.
 */
void ssl_connection(const u_char *buffer, unsigned data_len, int tcphdr_len,
                     uint16_t src_port, uint16_t dst_port,
                     char *src_addr, char *dst_addr,
                     long time, long microsec)
{
    pckt_info header;
    header.src_port = ntohs(src_port);
    header.start_time = time;
    header.start_microsec = microsec;
    header.end_time = time;
    header.end_microsec = microsec;

    // INFO (knowledge) FROM
    // SOURCE: https://stackoverflow.com/questions/3897883/how-to-detect-an-incoming-ssl-https-handshake-ssl-wire-format
    // AUTHOR: Jakub
    if (buffer[tcphdr_len] == 0x16 &&   //Handshake type Client-Hello SSLv3 and higher
    buffer[tcphdr_len + 5] == 0x01 &&
    ntohs(src_port) != 443) { //Handshake type Client-Hello SSLv3 and higher
        char *temp_SNI = get_TLS_SNI(buffer, tcphdr_len);
        if (!temp_SNI) {    //not found server name extension
            strcpy(header.sni, "(Could not find SNI)");
        }
        else {
            strcpy(header.sni, temp_SNI);
            free(temp_SNI);
        }
        strcpy(header.src_addr, src_addr);
        strcpy(header.dest_addr, dst_addr);
        header.ssl_ver = 1;
        header.packets = 1;
        header.last_found_size = 0;
        header.size = ntohs(*(uint32_t *) (&buffer[tcphdr_len + 3]));
        header.size += loop_packet(buffer, tcphdr_len+6, data_len, &header.last_found_size, NULL);
        DLInsertLast(&connection_list, header, ntohs(src_port));
    }
    else if ((buffer[tcphdr_len + 3] == 0x00) && (buffer[tcphdr_len + 4] == 0x02) &&    //SSLv2
               buffer[tcphdr_len + 2] == 0x01) { //Handshake Client-Hello SSLv2
        strcpy(header.src_addr, src_addr);
        strcpy(header.dest_addr, dst_addr);
        header.ssl_ver = 0;
        header.packets = 1;
        header.size = *(int_least8_t *)(&buffer[tcphdr_len + 1]);
        header.last_found_size = 0;
        strcpy(header.sni, "(SSLv2 no SNI provided)");
        DLInsertLast(&connection_list, header, ntohs(src_port));
    }
    else {  //adds info to the current connection, such as size, increment packet count, timestamp
        for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)) {
            if ((connection_list.Act->port == ntohs(src_port) &&
            (strcmp(connection_list.Act->data.dest_addr, src_addr) == 0 || strcmp(connection_list.Act->data.src_addr, src_addr) == 0)) ||
            (connection_list.Act->port == ntohs(dst_port) &&
            (strcmp(connection_list.Act->data.dest_addr, src_addr) == 0 || strcmp(connection_list.Act->data.src_addr, src_addr) == 0))) {
                connection_list.Act->data.end_time = time;
                connection_list.Act->data.end_microsec = microsec;
                connection_list.Act->data.packets += 1;
                if (connection_list.Act->data.ssl_ver == 1) {
                    uint32_t length = *(uint32_t *) (&buffer[tcphdr_len + 3]);
                    connection_list.Act->data.size += ntohs(length); // add bytes to all data transfered
                    if (ntohs(length) == connection_list.Act->data.last_found_size) {
                        connection_list.Act->data.size -= ntohs(length); // otherwise we will count that twice
                    }
                    int last_found = 0;
                    connection_list.Act->data.size += loop_packet(buffer, tcphdr_len, data_len, &last_found, NULL);
                    connection_list.Act->data.last_found_size = last_found;
                }
                else {
                    connection_list.Act->data.size +=  *(int_least8_t *)(&buffer[tcphdr_len + 1]);  //SSLv2
                }
                break;
            }
        }
    }
}

/*
*	Function for processing TCP packet
*	gets buffer and function gets
*	source and destination port and
*	source and destination ip's from IP header
*   returns 0 on success and -10 when malloc failed
*   if TCP packet carries SSL communication
*   the function process the SSL packet
*   further to the ssl_connection(...) function
* 	It is modification from
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi
*/
int tcp_packet(long time, long microsec, const u_char *buffer, bool ipv6, unsigned int data_len)
{
    int iphdr_len;
    char *temp_src = NULL;
    char *temp_dest = NULL;

    if (ipv6 == true) {
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
        iphdr_len = 40; //fixed size
        temp_src = readIPv6(iph->ip6_src);
        temp_dest = readIPv6(iph->ip6_dst);
    }
    else {
        struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
        iphdr_len = (int)iph->ip_hl*4;
        temp_src = readIPv4(iph->ip_src);
        temp_dest = readIPv4(iph->ip_dst);
    }
    if (temp_src == NULL|| temp_dest == NULL) {	//malloc error
        return -10;
    }
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4 ;

    int first_found, last_found, loop_length = 0;
    // Condition to find SSL packet in tcp payload
    // MODIFICATED function from:
    // SOURCE: https://www.netmeister.org/blog/tcpdump-ssl-and-tls.html
    // AUTHOR: jschauma
    if ((((buffer[tcphdr_len] == 0x14) ||                       //SSLv3 - TLS1.2
    (buffer[tcphdr_len] == 0x15) ||
    (buffer[tcphdr_len] == 0x16) ||
    (buffer[tcphdr_len] == 0x17)) &&
    (buffer[tcphdr_len+1] == 0x03 && (buffer[tcphdr_len+2] < 0x04)))   ||
    (((buffer[tcphdr_len] < 0x14) ||                            //SSLv2
    ((buffer[tcphdr_len] > 0x18) &&
    (buffer[tcphdr_len + 1] > 0x09))) &&
    (buffer[tcphdr_len+3] == 0x00) &&
    (buffer[tcphdr_len+4] == 0x02))) {
//        printf("MEF: %02x\n", buffer[tcphdr_len]);
        ssl_connection(buffer, data_len, tcphdr_len, tcph->th_sport, tcph->th_dport, temp_src, temp_dest, time, microsec);
    }
    else if ((loop_length = loop_packet(buffer, tcphdr_len - 3, data_len, &last_found, &first_found)) != 0) {
        for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)) {
            if ((connection_list.Act->port == ntohs(tcph->th_sport) &&
                 (strcmp(connection_list.Act->data.dest_addr, temp_src) == 0 ||
                  strcmp(connection_list.Act->data.src_addr, temp_src) == 0)) ||
                (connection_list.Act->port == ntohs(tcph->th_dport) &&
                 (strcmp(connection_list.Act->data.dest_addr, temp_src) == 0 ||
                  strcmp(connection_list.Act->data.src_addr, temp_src) == 0))) {
                connection_list.Act->data.end_time = time;
                connection_list.Act->data.end_microsec = microsec;
                connection_list.Act->data.packets += 1;
                connection_list.Act->data.size += loop_length; // add bytes to all data transfered
//                printf("data %d\n", first_found);
                if (first_found == connection_list.Act->data.last_found_size) {
                    connection_list.Act->data.size -= first_found; // otherwise we will count that twice
                }
                else if (last_found == connection_list.Act->data.last_found_size) {
                    connection_list.Act->data.size -= last_found; // otherwise we will count that twice
                }
                else if (loop_length == connection_list.Act->data.last_found_size) {
                    connection_list.Act->data.size -= loop_length; // otherwise we will count that twice
                }
                connection_list.Act->data.last_found_size = last_found;
            }
        }
    }

    // FIN flag - TCP connection is closing
    // so SSL connection was closed as well
    // with the last SSL packet of that connection
    if (tcph->th_flags & TH_FIN && ntohs(tcph->th_sport) == 443) {
        print_data(tcph->th_sport, tcph->th_dport, temp_src, temp_dest);
    }
    free(temp_src);
    free(temp_dest);
    return 0;
}



/*
*	Gets the whole packet, calls functions for packet parsing
*	MODIFICATED function from:
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi 
*/
void callback(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* buffer)
{
	signal(SIGINT, intHandler); 		//to properly catch CTRL+C
	struct ether_header *p = (struct ether_header *) buffer;
	bool ipv6 = false;
	int tcp_switch;
	if (ntohs(p->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        ipv6 = true;
    }
	args = NULL; // for not having a warning of unused variable
    const unsigned int data_len = (pkthdr->len);
	//Get the IP Header part of this packet , excluding the ethernet header
	if (ipv6 == true) {
		struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
		tcp_switch = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	}
	else {
		struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
		tcp_switch = iph->ip_p;
	}

	if (tcp_switch == 6) {  //TCP Protocol, just to be sure, even when we have TCP filter
            tcp_packet(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, buffer, ipv6, data_len);
    }

}

/*
 * setup the connection either from the pcap/pcapng file
 * or to the actual network device
 * returns NULL on error
 * returns pcap_t type on success
 */
pcap_t *set_up(int mode,char *iface,char *rfile)
{
	struct bpf_program fp;        // to hold compiled program
    char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	bpf_u_int32 pMask;            // subnet mask 
	bpf_u_int32 pNet;             // ip address
    pcap_t *sniff;

    // fetch the network address and network mask
    long iface_num;
    char *check;
    if (iface) { iface_num = strtol(iface, &check, 10); }
    if (iface && check[0] == '\0') {
        pcap_if_t *iface_list;
        if (pcap_findalldevs(&iface_list, errbuf) == -1) {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
            return NULL;
        }
        else {
            for (int i = 1; i <= iface_num; i++ ) {
                if (!iface_list) { break; }
                if (i == iface_num) {
                    strcpy(iface, iface_list->name);
                    break;
                }
                iface_list = iface_list->next;
            }
        }
    }

	if (pcap_lookupnet(iface, &pNet, &pMask, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	// Opens device for sniffing
	if (mode == 10) {   // -r -reading from pcapng file
        char *file_check = realpath(rfile, NULL);
        if (!file_check) {
            fprintf(stderr, "File '%s' does not exist.\n", rfile);
            return NULL;
        }
        sniff = pcap_open_offline(rfile, errbuf); //https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
    }
	else {              // listen from the device
        sniff = pcap_open_live(iface, BUFSIZ, 0, 1000, errbuf);
    }
	//
	if(sniff == NULL)
	{
		fprintf(stderr, "pcap_open failed due to [%s]\n", errbuf);
		return NULL;
	}

	//sets the filter only to TCP packets
	//source: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
	if(pcap_compile(sniff, &fp, "tcp ", 0, pNet) == -1)	
	{
		fprintf(stderr, "pcap_compile() failed\n");
		return NULL;
	}
	if(pcap_setfilter(sniff, &fp) == -1)
	{
		fprintf(stderr, "pcap_setfilter() failed\n");
		return NULL;
	}
	return sniff;
}


/*
 * main body of the ssl monitor
 * returns 0 on success
 * returns 1 on malloc error
 */
int main(int argc, char *argv[])
{
    DLInitList(&connection_list);                   //initialize the list for connections
	char *iface = malloc(41 * sizeof(char));	//interface
	char *rfile = malloc(201 * sizeof(char));	//pcapng file
	if (iface == NULL) { return 1; }                //malloc error
	if (rfile == NULL) { return 1; }                //malloc error
    //TODO check file validity to be more robust
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

	pcap_t *sniff = set_up(args, iface, rfile);
	if (sniff) {
        // Loop for catching packets, ends after EOF or keyboard interrupt
        pcap_loop(sniff, -1 , callback, NULL);
	}

	// deallocate the used memory
	DLDisposeList(&connection_list);
	if (iface) { free(iface); }
	if (rfile) { free(rfile); }
	return 0;
}
