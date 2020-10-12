/*******************************************
	NAME:			SSL connection monitor
	DESCRIPTION:	Catch SSLv2 to TLSv1.2 connection and outputs info about it
	AUTHOR:			Dominik Boboš (xbobos00)
	AC.YEAR:		2020/2021
********************************************/


#include "ssl-sniffer.h"
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
#include <netinet/ip.h>			// Libs for sniffing 	//
#include <netinet/tcp.h>		//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h> 		//////////////////////////
//sudo apt-get install libpcap0.8-dev


tDLList connection_list; //list to track SSL/TLS connections

int show_interfaces()
{
	char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	pcap_if_t *alldevs, *dlist;
	int i = 0;
	  // Shows list of the all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
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
        if (dlist->description)
            printf(" (%s)\n", dlist->description);
        else
            printf("(No description)\n");
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
	puts("HELP:");
	puts("-i <interface> interface, where the SSL monitor captures the connection");
	puts("-r <file> pcapng file to get SSL connection from ");
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
			if (strlen(optarg) > 40)
			{
				fprintf(stderr, "Parameter for interface could not be longer than 40 characters!\n");
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
void print_data(uint16_t src_port, uint16_t dst_port)
{
    for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)){
        if (connection_list.Act->port == ntohs(src_port) || connection_list.Act->port == ntohs(dst_port)) {
            long duration_sec = connection_list.Act->data.end_time - connection_list.Act->data.start_time;
            long duration_usec = connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
            if (duration_usec < 0) {
                duration_usec = 1000000 + connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
                duration_sec -= 1; //i use the second for micro seconds
            }
            char datetime[50];
            strftime(datetime,sizeof(datetime),"%Y-%m-%d %H:%M:%S", localtime(&connection_list.Act->data.start_time));
            printf("%s.%06ld,%s,%u,%s,%s,%d,%d,%ld.%06ld\n\n", datetime, connection_list.Act->data.start_microsec,
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
 */
char *get_TLS_SNI(unsigned char *buffer, int tcphdr_len)
{
    int x =  *(int_least8_t *)(&buffer[tcphdr_len + 43]);   //session ID length
    int y = ntohs(*(uint32_t *)(&buffer[tcphdr_len + 43 + x + 1])); // cipher suites length
    int pos = tcphdr_len + 43 + x + 1 + y ;                         // position in byte array
    int extenstion_length = ntohs(*(uint32_t *)(&buffer[pos + 4]));
    int length = 0;                                                 // server name length
    for (int i = 6; i < extenstion_length;){
        if (ntohs(*(uint32_t *)(&buffer[pos + i])) == 0) {  // type server name (0x0000 == 0)
            length = ntohs(*(uint32_t *)(&buffer[pos + i + 7]));  //server name length
            pos = pos + i + 9;                                            //updates position - place where SNI is
            break;
        }
        else {
            i += 2;
            i += ntohs(*(uint32_t *)(&buffer[pos + i])) + 2 ;
        }
    }
    if (length < 1) { return NULL; }
    char *SNI = malloc(length+1 * sizeof(char));
    if (!SNI) {	return NULL; }
    for(int i = 0; i < length; i++){
        SNI[i] = (char *)(buffer[pos + i]);
    }
    SNI[length] = '\0';
    return SNI;
}


// returns the real length of payload if there is more TLS packets sticked together
// if no occurences it returns 0
int loop_packet (const u_char *buffer, int tcphdr_len, unsigned int data_len, bool finding_TLS) {
    int payload_size = 0;
    if (finding_TLS == false)
        tcphdr_len += 3;    //offset to not count the payload we have already counted
    for(int i = 0; i < (int)data_len -5; i++) {
        if (((buffer[tcphdr_len + i] == 0x14) ||
             (buffer[tcphdr_len + i] == 0x15) ||
             (buffer[tcphdr_len + i] == 0x17)) &&
            (buffer[tcphdr_len + 1 + i] == 0x03 && (buffer[tcphdr_len + 2 + i] < 0x04))) {
            uint32_t length = *(uint32_t *)(&buffer[tcphdr_len + i + 3]);
            payload_size += ntohs(length);
        }
    }
    return payload_size;
}

void ssl_connection (const u_char *buffer, unsigned data_len, int tcphdr_len, uint16_t src_port, uint16_t dst_port, char *src_addr, char *dst_addr, long time, long microsec)
{
    pckt_info header;
    strcpy(header.src_addr, src_addr);
    strcpy(header.dest_addr, dst_addr);
    free(src_addr);
    free(dst_addr);
    header.src_port = ntohs(src_port);
    header.start_time = time;
    header.start_microsec = microsec;
    header.end_time = time;
    header.end_microsec = microsec;

//        //https://stackoverflow.com/questions/3897883/how-to-detect-an-incoming-ssl-https-handshake-ssl-wire-format
    if (buffer[tcphdr_len] == 0x16 && buffer[tcphdr_len + 5] == 0x01 &&
        ntohs(src_port) != 443) { //Handshake type Client-Hello SSLv3 and higher
        char *temp_SNI = get_TLS_SNI(buffer, tcphdr_len);
        if (!temp_SNI) {    //not found server name extension
            strcpy(header.sni, "(Could not find SNI)");
        } else {
            strcpy(header.sni, temp_SNI);
            free(temp_SNI);
        }
        header.ssl_ver = 1;
        header.packets = 1;
        header.size = ntohs(*(uint32_t *) (&buffer[tcphdr_len + 3]));
        header.size += loop_packet(buffer, tcphdr_len, data_len, false);
        DLInsertLast(&connection_list, header, ntohs(src_port));

    } else if ((buffer[tcphdr_len + 3] == 0x00) && (buffer[tcphdr_len + 4] == 0x02) &&    //SSLv2
               buffer[tcphdr_len + 2] == 0x01) { //handshake Client-Hello SSLv2
        header.ssl_ver = 0;
        header.packets = 1;
        header.size = ((buffer[tcphdr_len] & 0x7f) << 8 | buffer[tcphdr_len + 1]); //ntohs(buffer[]); //test it pls
        strcpy(header.sni, "(SSLv2 no SNI provided)");
        DLInsertLast(&connection_list, header, ntohs(src_port));
    } else {

        for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)) {
            if (connection_list.Act->port == ntohs(src_port) ||
                connection_list.Act->port == ntohs(dst_port)) {
                connection_list.Act->data.end_time = time;
                connection_list.Act->data.end_microsec = microsec;
                connection_list.Act->data.packets += 1;
                if (connection_list.Act->data.ssl_ver == 1) {
                    uint32_t length = *(uint32_t *) (&buffer[tcphdr_len + 3]);
                    connection_list.Act->data.size += ntohs(length); // add bytes to all data transfered
                    connection_list.Act->data.size += loop_packet(buffer, tcphdr_len, data_len, false);
                } else {
                    connection_list.Act->data.size += ((buffer[tcphdr_len] & 0x7f) << 8 |
                                                       buffer[tcphdr_len + 1]);  //SSLv2
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
* 	It is modification from
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi
*/
int tcp_packet(long time, long microsec, const u_char *buffer, bool ipv6, unsigned int data_len)
{
    pckt_info header;
    int iphdr_len;
    char *temp_src = NULL;
    char *temp_dest = NULL;

    if (ipv6 == true)
    {
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
        iphdr_len = 40; //fixed size
        temp_src = readIPv6(iph->ip6_src);
        temp_dest = readIPv6(iph->ip6_dst);
    }
    else
    {
        struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
        iphdr_len = iph->ip_hl*4;
        temp_src = readIPv4(iph->ip_src);
        temp_dest = readIPv4(iph->ip_dst);
    }
    if (temp_src == NULL|| temp_dest == NULL) {	//malloc error
        return -10;
    }

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
    unsigned tcp = iphdr_len + sizeof(struct ether_header);
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4 ;



    // Condition to find SSL packet in tcp payload
    // MODIFICATED function from:
    // SOURCE: https://www.netmeister.org/blog/tcpdump-ssl-and-tls.html
    // AUTHOR: jschauma
    if ((((buffer[tcphdr_len] == 0x14) ||
    (buffer[tcphdr_len] == 0x15) ||
    (buffer[tcphdr_len] == 0x17)) &&
    (buffer[tcphdr_len+1] == 0x03 && (buffer[tcphdr_len+2] < 0x04)))   ||
    ((buffer[tcphdr_len] == 0x16) &&
    (buffer[tcphdr_len+1] == 0x03) && (buffer[tcphdr_len+2] < 0x04) &&
    (buffer[tcphdr_len+9] == 0x03) && (buffer[tcphdr_len+10] < 0x04))    ||
    (((buffer[tcphdr_len] < 0x14) ||
    ((buffer[tcphdr_len] > 0x18) &&
    (buffer[tcphdr_len + 1] > 0x09))) &&
    (buffer[tcphdr_len+3] == 0x00) &&
    (buffer[tcphdr_len+4] == 0x02)))
    {
        ssl_connection(buffer, data_len, tcphdr_len, tcph->th_sport, tcph->th_dport, temp_src, temp_dest, time, microsec);
    }

    // FIN flag - TCP connection is closing
    // so SSL connection was closed as well
    // with the last SSL packet of that connection
    if (tcph->th_flags & TH_FIN ) {
        print_data(tcph->th_sport, tcph->th_dport);
    }
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
	int tcp_switch = 0;
	if (ntohs(p->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        ipv6 = true;
    }
	args = NULL; // for not having a warning of unused variable
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);

	//Get the IP Header part of this packet , excluding the ethernet header
	if (ipv6 == true)
	{
		struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
		tcp_switch = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	}
	else
	{
		struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
		tcp_switch = iph->ip_p;
	}
	switch (tcp_switch) //Check the Protocol and do accordingly... just to be sure, even when we have TCP filter
	{
		case 6:  //TCP Protocol
			tcp_packet(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, buffer, ipv6, data_len);
			break;
	}
}


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
        if (pcap_findalldevs(&iface_list, errbuf) == -1)
        {
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

	if (pcap_lookupnet(iface, &pNet, &pMask, errbuf) == -1)
	{
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	// Opens device for sniffing
	if (mode == 0){     //help printed
	    return NULL;
	}
	if (mode == 10) 
		sniff = pcap_open_offline(rfile, errbuf); //https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
	else 
		sniff = pcap_open_live(iface, BUFSIZ, 0, 1000, errbuf);

	if(sniff == NULL)
	{
		fprintf(stderr, "pcap_open failed due to [%s]\n", errbuf);
		return NULL;
	}

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

int main(int argc, char *argv[])
{
    DLInitList(&connection_list);
	char *iface = malloc(41 * sizeof(char));	//interface
	char *rfile = malloc(201 * sizeof(char));		//pcapng file
	if (iface == NULL) { return 1; }
	if (rfile == NULL) { return 1; }
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

	// printf("interface=%s, pcapng file=%s\n", iface, rfile);
	pcap_t *sniff = set_up(args, iface, rfile);
	if (sniff) {
        // Loop for catching packets, ends after pnum packets were catched
        pcap_loop(sniff, -1 , callback, NULL);
	}

	DLDisposeList(&connection_list);

	if (iface) {
		free(iface);
	}
	if (rfile) {
		free(rfile);
	}
	return 0;
}