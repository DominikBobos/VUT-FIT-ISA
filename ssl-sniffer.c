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
//#include <ctype.h>				//	C-dependencies		//
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


/*
*	Struct with needed info
* 	for output
*/
typedef struct pckt_info
{
    char src_addr[1025];	//contains source IP
    char dest_addr[1025];	//contains destination IP
    unsigned src_port;		//contains source  PORT
    unsigned dest_port;		//contains destination  PORT
    char sni[1025];         // SNI
    long start_time;         //
    long start_microsec;
    long end_time;         //
    long end_microsec;
    int packets;             // packets count in connection
    int size;                // data in Bytes transfered in connection
    int ssl_ver;            // 0 for SSLv2 1 for SSLv3,TLSv1.0,1.1,1.2

} pckt_info;

typedef struct tDLElem {                 /* prvek dvousměrně vázaného seznamu */
    int port;
    struct pckt_info data;                                            /* užitečná data */
    struct tDLElem *lptr;          /* ukazatel na předchozí prvek seznamu */
    struct tDLElem *rptr;        /* ukazatel na následující prvek seznamu */
} *tDLElemPtr;

typedef struct {                                  /* dvousměrně vázaný seznam */
    tDLElemPtr First;                      /* ukazatel na první prvek seznamu */
    tDLElemPtr Act;                     /* ukazatel na aktuální prvek seznamu */
    tDLElemPtr Last;                    /* ukazatel na posledni prvek seznamu */
} tDLList;


void DLInitList (tDLList *L) {
/*
** Provede inicializaci seznamu L před jeho prvním použitím (tzn. žádná
** z následujících funkcí nebude volána nad neinicializovaným seznamem).
** Tato inicializace se nikdy nebude provádět nad již inicializovaným
** seznamem, a proto tuto možnost neošetřujte. Vždy předpokládejte,
** že neinicializované proměnné mají nedefinovanou hodnotu.
**/

///tym ze inicializujem, vsetko nastavim na NULL lebo este nic ine nemam
    L->Act = NULL;
    L->Last = NULL;
    L->First = NULL;
}

void DLDisposeList (tDLList *L) {
/*
** Zruší všechny prvky seznamu L a uvede seznam do stavu, v jakém
** se nacházel po inicializaci. Rušené prvky seznamu budou korektně
** uvolněny voláním operace free.
**/

///pripad kedy je list prazdny
    if(L->First == NULL && L->Act == NULL && L->Last == NULL)
    {
        return;
    }

    struct tDLElem *elem_ptr = L->First;

    while(elem_ptr->rptr != NULL)
    {
        elem_ptr = elem_ptr->rptr;	///postupne prechadzam po zozname
        free(elem_ptr->lptr);
    }
    free(elem_ptr);		///uvolnenie posledneho lebo cyklus skoncil na poslednom

    DLInitList(L);
}

void DLInsertFirst (tDLList *L, pckt_info val, int port) {
/*
** Vloží nový prvek na začátek seznamu L.
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci DLError().
**/

    struct tDLElem *new_elem = (struct tDLElem *) malloc(sizeof(struct tDLElem));
    if(new_elem == NULL)	///kontrola uspesnosti malloc
    {
        return;
    }
    new_elem->port = port;
    new_elem->data = val;
    new_elem->rptr = L->First; 			///novy vlozeny elem napravo ukazuje na predtym prveho
    new_elem->lptr = NULL; 				/// novy vlozeny elem nalavo ukazuje na NULL

    if (L->First != NULL) { 			///tam uz prvy bol
        L->First->lptr = new_elem; 			///Stary prvy uz nebude ukazovat nalavo na NULL ale na novy prvy

    }
    else{ 								/// insert do prázdného listu
        L->Last = new_elem;
    }

    L->First = new_elem;				/// nastavenie ukazatela na začiatok
}

void DLInsertLast(tDLList *L, pckt_info val, int port) {
/*
** Vloží nový prvek na konec seznamu L (symetrická operace k DLInsertFirst).
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci DLError().
**/

    struct tDLElem *new_elem = (struct tDLElem *) malloc(sizeof(struct tDLElem));
    if(new_elem == NULL)	///kontrola uspesnosti malloc
    {
        return;
    }
    new_elem->port = port;
    new_elem->data = val;
    new_elem->rptr = NULL; 				///novy vlozeny elem napravo ukazuje na NULL
    new_elem->lptr = L->Last; 			/// novy vlozeny elem nalavo ukazuje na predtym posledny

    if (L->Last != NULL) { 				/// tam uz bol posledny
        L->Last->rptr = new_elem; 			///Stary posledny uz nebude ukazovat napravo na NULL ale na novy prvy

    }
    else{ 								/// insert do prázdného listu
        L->First = new_elem;
    }

    L->Last = new_elem;				/// nastavenie ukazatela noveho prvku na koniec
}

void DLFirst (tDLList *L) {
/*
** Nastaví aktivitu na první prvek seznamu L.
** Funkci implementujte jako jediný příkaz (nepočítáme-li return),
** aniž byste testovali, zda je seznam L prázdný.
**/

    L->Act = L->First;
}

void DLLast (tDLList *L) {
/*
** Nastaví aktivitu na poslední prvek seznamu L.
** Funkci implementujte jako jediný příkaz (nepočítáme-li return),
** aniž byste testovali, zda je seznam L prázdný.
**/
    L->Act = L->Last;
}

void DLCopyFirst (tDLList *L, int *port) {
/*
** Prostřednictvím parametru val vrátí hodnotu prvního prvku seznamu L.
** Pokud je seznam L prázdný, volá funkci DLError().
**/
    if (L->First == NULL)
        return;
    else
        *port = L->First->port;
}

void DLCopyLast (tDLList *L, int *port) {
/*
** Prostřednictvím parametru val vrátí hodnotu posledního prvku seznamu L.
** Pokud je seznam L prázdný, volá funkci DLError().
**/
    if (L->First == NULL)
        return;
    else
        *port = L->Last->port;
}

void DLDeleteFirst (tDLList *L) {
/*
** Zruší první prvek seznamu L. Pokud byl první prvek aktivní, aktivita
** se ztrácí. Pokud byl seznam L prázdný, nic se neděje.
**/
    if (L->First == NULL)
        return;

    struct tDLElem *elem_ptr = L->First;

    if(L->First == L->Last)
    {
        DLInitList(L);			///ak je v liste jediny prvok tak zanikne a inicialzujeme znova
    }
    else if (L->First == L->Act)
    {
        L->Act = NULL;
        L->First = L->First->rptr;
        L->First->lptr = NULL;
    }
    else
    {
        L->First = L->First->rptr;
        L->First->lptr = NULL;
    }

    free(elem_ptr);
}

void DLDeleteLast (tDLList *L) {
/*
** Zruší poslední prvek seznamu L. Pokud byl poslední prvek aktivní,
** aktivita seznamu se ztrácí. Pokud byl seznam L prázdný, nic se neděje.
**/
    if (L->First == NULL)
        return;
    else
    {
        struct tDLElem *elem_ptr = L->Last;

        if(L->First == L->Last)
        {
            DLInitList(L);		///ak je v liste jediny prvok tak zanikne a inicialzujeme znova
        }
        else if (L->Last == L->Act)
        {
            L->Act = NULL;
            L->Last = L->Last->lptr;
            L->Last->rptr = NULL;
        }
        else
        {
            L->Last = L->Last->lptr;
            L->Last->rptr = NULL;
        }


        free(elem_ptr);
    }
}

void DLPostDelete (tDLList *L) {
/*
** Zruší prvek seznamu L za aktivním prvkem.
** Pokud je seznam L neaktivní nebo pokud je aktivní prvek
** posledním prvkem seznamu, nic se neděje.
**/
    if(L->First == NULL && L->Act == NULL && L->Last == NULL) ///ked je prazdny list
    {
        return;
    }

    if((L->Act == L->Last ) || (L->Act == NULL))
        return;
    else
    {
        struct tDLElem *elem_ptr = L->Act->rptr;		///nastavim na prvok ktory chcem mazat
        if (elem_ptr == L->Last)						///pripad kedy je mazany prvok aj poslednym
        {
            L->Act->rptr = NULL;
            L->Last = L->Act;
        }
        else
        {
            struct tDLElem *elem_ptr_next = elem_ptr->rptr;	///nastavim na prvok napravo od mazaneho
            L->Act->rptr = elem_ptr_next;			///aktivny ukazuje na prvok napravo za mazanym
            elem_ptr_next->lptr = L->Act;			///nalavo od mazaneho prvku ukazuje na aktivny
        }
        free(elem_ptr);
    }
}

void DLPreDelete (tDLList *L) {
/*
** Zruší prvek před aktivním prvkem seznamu L .
** Pokud je seznam L neaktivní nebo pokud je aktivní prvek
** prvním prvkem seznamu, nic se neděje.
**/
    if(L->First == NULL && L->Act == NULL && L->Last == NULL) ///ked je list prazdny
    {
        return;
    }

    if((L->Act == L->First ) || (L->Act == NULL))
        return;
    else
    {
        struct tDLElem *elem_ptr = L->Act->lptr;		///nastavim na prvok ktory chcem mazat
        if (elem_ptr == L->First)		///pripad kedy je mazany prvok aj prvym
        {
            L->Act->lptr = NULL;
            L->First = L->Act;
        }
        else
        {
            struct tDLElem *elem_ptr_next = elem_ptr->lptr;	///nastavim na prvok nalavo od mazaneho
            L->Act->lptr = elem_ptr_next;			///aktivny ukazuje na prvok nalavo od mazaneho
            elem_ptr_next->rptr = L->Act;			///nalavo od mazaneho prvku ukazuje na aktivny
        }

        free(elem_ptr);
    }
}

void DLPostInsert (tDLList *L, pckt_info val, int port) {
/*
** Vloží prvek za aktivní prvek seznamu L.
** Pokud nebyl seznam L aktivní, nic se neděje.
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci DLError().
**/

    if (L->Act == NULL)
        return;
    else
    {
        struct tDLElem *new_elem = (struct tDLElem *) malloc(sizeof(struct tDLElem));

        if(new_elem == NULL)	///kontrola uspesnosti malloc
        {
            return;
        }
        else if (L->Act == L->Last)
        {
            L->Act->rptr = new_elem;
            new_elem->lptr = L->Act;
            new_elem->rptr = NULL;
            L->Last = new_elem;
            new_elem->data = val;
            new_elem->port = port;
        }
        else
        {
            struct tDLElem *elem_ptr = L->Act->rptr;		///ukazatel na prvok za aktivnym
            L->Act->rptr = new_elem;
            elem_ptr->lptr = new_elem;
            new_elem->lptr = L->Act;
            new_elem->rptr = elem_ptr;
            new_elem->data = val;
        }
    }
}

void DLPreInsert (tDLList *L, pckt_info val, int port) {
/*
** Vloží prvek před aktivní prvek seznamu L.
** Pokud nebyl seznam L aktivní, nic se neděje.
** V případě, že není dostatek paměti pro nový prvek při operaci malloc,
** volá funkci DLError().
**/

    if (L->Act == NULL)
        return;
    else
    {
        struct tDLElem *new_elem = (struct tDLElem *) malloc(sizeof(struct tDLElem));
        if(new_elem == NULL)	///kontrola uspesnosti malloc
        {
            return;
        }
        else if (L->Act == L->First)
        {
            L->Act->lptr = new_elem;
            new_elem->rptr = L->Act;
            new_elem->lptr = NULL;
            L->First = new_elem;
            new_elem->data = val;
            new_elem->port = port;

        }
        else
        {
            struct tDLElem *elem_ptr = L->Act->lptr;		///ukazatel na prvok pred aktivnym
            L->Act->lptr = new_elem;
            elem_ptr->rptr = new_elem;
            new_elem->rptr = L->Act;
            new_elem->lptr = elem_ptr;
            new_elem->data = val;

        }
    }
}

void DLCopy (tDLList *L, int *port) {
/*
** Prostřednictvím parametru val vrátí hodnotu aktivního prvku seznamu L.
** Pokud seznam L není aktivní, volá funkci DLError ().
**/
    if (L->Act == NULL)
        return;
    else
        *port = L->Act->port;
}

void DLActualize (tDLList *L, pckt_info val, int port) {
/*
** Přepíše obsah aktivního prvku seznamu L.
** Pokud seznam L není aktivní, nedělá nic.
**/
    if (L->Act == NULL)
        return;
    else
        L->Act->port = port;
        L->Act->data = val;
}

void DLSucc (tDLList *L) {
/*
** Posune aktivitu na následující prvek seznamu L.
** Není-li seznam aktivní, nedělá nic.
** Všimněte si, že při aktivitě na posledním prvku se seznam stane neaktivním.
**/
    if (L->Act == NULL)
        return;
    else
    {
        if(L->Last == L->Act)
            L->Act = NULL;
        else
        {
            L->Act = L->Act->rptr;
        }
    }
}


void DLPred (tDLList *L) {
/*
** Posune aktivitu na předchozí prvek seznamu L.
** Není-li seznam aktivní, nedělá nic.
** Všimněte si, že při aktivitě na prvním prvku se seznam stane neaktivním.
**/

    if (L->Act == NULL)
        return;
    else
    {
        if(L->First == L->Act)
            L->Act = NULL;
        else
        {
            L->Act = L->Act->lptr;
        }
    }
}

int DLActive (tDLList *L) {
/*
** Je-li seznam L aktivní, vrací nenulovou hodnotu, jinak vrací 0.
** Funkci je vhodné implementovat jedním příkazem return.
**/
    return (L->Act != NULL)? 1 : 0 ;
}


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

/*
*	Function to properly catch keyboard interruptions
*/
void intHandler()
{
    DLDisposeList(&connection_list);
    exit(0);
}

int print_help() 
{
	puts("HELP:");
	puts("-i <interface> interface, where the SSL monitor captures the connection");
	puts("-r <file> pcapng file to get SSL connection from ");
	return 0;
}


///*
//*	Struct with needed info
//* 	for output
//*/
//struct pckt_info
//{
//    char src_addr[1025];	//contains source IP or FQDN
//    char dest_addr[1025];	//contains destination IP or FQDN
//    unsigned src_port;		//contains source  PORT
//    unsigned dest_port;		//contains destination  PORT
//    int header_size;		// size of the full packet header
//    long start_time;         //
//    long start_microsec;
//    int packets;             // packets count in connection
//    int size;                // data in Bytes transfered in connection
//};


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

// /*
// *	Function for right output format
// *	prints spaces 'count' times
// */
// void add_space(int count)
// {
//     if (count <= 22)	//because of the extra space between 8 bytes
//         --count;
//     char spaces[count];
//     for (int i = 0; i < count; i++)
//         spaces[i] = ' ';
//     spaces[count] = '\0';
//     printf("%s",spaces);
// }

void print_data(char *time, long microsec, pckt_info packet_info,
                 const unsigned data_len, const u_char *data)
{
	if (packet_info.src_port == 443) {
		printf("%s.%ld,%s,%u,%s\n\n", time, microsec,
	    packet_info.dest_addr, packet_info.dest_port,
	    packet_info.src_addr);
	}
	else {
		printf("%s.%ld,%s,%u,%s\n\n", time, microsec,
	    packet_info.src_addr, packet_info.src_port,
	    packet_info.dest_addr);
	}
}
//     int header_end = packet_info.header_size;	// header size
//     char ascii;									// variable for printing in ascii
//     int end_case = 0;							// to correctly show first column
//     int underflow = 0;
//     for (int i = 0; i <= (int)data_len/16+1; i++)
//     {
//         //this is magic, and hours of thinking //forgive me this, but it works
//         end_case += 16;
//         if (i*16 < header_end && header_end <= (i+1)*16) {
//             end_case = header_end;
//             printf("0x%04x",header_end);
//         }
//         else if (end_case > (int)data_len){
//             printf("0x%04x",(int)data_len);
//         }
//         else if (end_case == (int)data_len){
//             printf("--------------------------------------------------------------------------\n\n");
//             break;
//         }
//         else {
//             printf("0x%04x",end_case);
//         }

//         for (int k = 0; k < 16; k++)
//         {
//             if (i*16+k-underflow == (int)data_len) {add_space((16 - k)*3+1); break;}
//             if (i*16+k == header_end) { add_space((16 - k)*3+1); break;}
//             if (k == 8) {printf(" ");}
//             printf(" %02x", data[i*16+k-underflow] & 0xff);
//         }
//         printf("  ");
//         for (int k = 0; k < 16; k++)
//         {
//             if (i*16+k-underflow == (int)data_len) {
//                 printf("\n--------------------------------------------------------------------------\n\n");
//                 return;
//             }
//             if (i*16+k == header_end) {
//                 underflow = i*16 - header_end + 16;
//                 printf("\n"); break;
//             }
//             if (k == 8) {printf(" ");}
//             ascii = data[i*16+k-underflow];
//             if (!isprint((int)ascii)) {ascii = 46;}
//             printf("%c", ascii);
//         }
//         printf("\n");
//     }

// }



/*
*	Gets FQDN from IP, when FQDN could not be found
*	returns IP address back
*	MODIFICATED from
*	SOURCE: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
* 	AUTHOR: algorism
*/
char *host_name(struct in_addr ip_addr)
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
*	Gets FQDN from IPv6, when FQDN could not be found
*	returns IP address back
*	MODIFICATED from
*	SOURCE: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
* 	AUTHOR: algorism
*/
char *host_nameIPv6(struct in6_addr ip_addr)
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

char *get_TLS_SNI(unsigned char *buffer, int tcphdr_len)
{
    int x =  *(int_least8_t *)(&buffer[tcphdr_len + 43]);
    int y = ntohs(*(uint32_t *)(&buffer[tcphdr_len + 43 + x + 1]));
    uint32_t temp = *(uint32_t *)(&buffer[tcphdr_len + 43 + x + 1 + y + 13]);
    int length = ntohs(temp);
    if (length < 1) { return NULL; }

    char *SNI = malloc(length+1 * sizeof(char));
    if (!SNI) {	return NULL; }
    for(int i = 0; i < length; i++){
        SNI[i] = (char *)(buffer[tcphdr_len + 43 + x + 1 + y + 15 + i]);
    }
    SNI[length] = '\0';
    return SNI;
//    unsigned char *curr;
//    unsigned char sidlen = bytes[43];
//    curr = bytes + 1 + 43 + sidlen;
//    unsigned short cslen = ntohs(*(unsigned short*)curr);
//    curr += 2 + cslen;
//    unsigned char cmplen = *curr;
//    curr += 1 + cmplen;
//    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
//    curr += 2;
//    unsigned short ext_type = 1;
//    unsigned short ext_len;
//    while(curr < maxchar && ext_type != 0)
//    {
//        ext_type = ntohs(*(unsigned short*)curr);
//        curr += 2;
//        ext_len = ntohs(*(unsigned short*)curr);
//        curr += 2;
//        if(ext_type == 0)
//        {
//            curr += 3;
//            unsigned short namelen = ntohs(*(unsigned short*)curr);
//            curr += 2;
//            return (char*)curr;
//        }
//        else curr += ext_len;
//    }
//    if (curr != maxchar) return ("incomplete SSL Client Hello");
//    return NULL; //SNI was not present
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
            payload_size += ntohs(length); //test it pls
//            printf("HIT ");
        }
    }
//    printf("Segment size = %d ,loop_packet = %d\n", data_len, payload_size);
    return payload_size;
}



/*
*	Function for processing TCP protocol
*	gets buffer and function gets from it
*	source and destination port and
*	source and destination ip's from IP header
*	returns struct pckt_info
* 	It is modification from
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi
*/
void tcp_packet(long time, long microsec, const u_char *buffer, bool ipv6, unsigned int data_len)
{
    pckt_info header;
    int iphdr_len;
    char *temp_src = NULL;
    char *temp_dest = NULL;

    if (ipv6 == true)
    {
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
        iphdr_len = 40; //fixed size
        temp_src = host_nameIPv6(iph->ip6_src);
        temp_dest = host_nameIPv6(iph->ip6_dst);
    }
    else
    {
        struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
        iphdr_len = iph->ip_hl*4;
        temp_src = host_name(iph->ip_src);
        temp_dest = host_name(iph->ip_dst);
    }
    if (temp_src == NULL|| temp_dest == NULL) {	//malloc error
        return ;
    }

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
    unsigned tcp = iphdr_len + sizeof(struct ether_header);
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4 ;
    strcpy(header.src_addr, temp_src);
    strcpy(header.dest_addr, temp_dest);
    free(temp_src);
    free(temp_dest);
    header.src_port = ntohs(tcph->th_sport);
    header.dest_port = ntohs(tcph->th_dport);
    header.start_time = time;
    header.start_microsec = microsec;


    int finding_TLS = 0;
//    if (connection_list.First) {
//        for (DLFirst(&connection_list); connection_list.Act != NULL ; DLSucc(&connection_list)) {
//            if (((connection_list.Act->data.src_port == ntohs(tcph->th_sport) && connection_list.Act->data.dest_port == ntohs(tcph->th_dport)) ||
//            (connection_list.Act->data.dest_port == ntohs(tcph->th_sport) && connection_list.Act->data.src_port == ntohs(tcph->th_dport))) &&
//            connection_list.Act->data.ssl_ver == 1) {
//                finding_TLS = loop_packet(buffer, tcphdr_len, data_len, true);  // when in TLSv3 are segments ordered differently
//                break;
//            }
//        }
//    }
//    printf(" %02x ", buffer[tcphdr_len ] & 0xff);
//    printf(" %02x\n", buffer[tcphdr_len +1] & 0xff);
    //https://www.netmeister.org/blog/tcpdump-ssl-and-tls.html
    if ((((buffer[tcphdr_len] == 0x14) ||
    (buffer[tcphdr_len] == 0x15) ||
    (buffer[tcphdr_len] == 0x17)) &&
    (buffer[tcphdr_len+1] == 0x03 && (buffer[tcphdr_len+2] < 0x04)))   ||
    ((buffer[tcphdr_len] == 0x16) &&
    (buffer[tcphdr_len+1] == 0x03) && (buffer[tcphdr_len+2] < 0x04) &&
    (buffer[tcphdr_len+9] == 0x03) && (buffer[tcphdr_len+10] < 0x04))    ||
    (((buffer[tcphdr_len] < 0x14) ||
    (buffer[tcphdr_len] > 0x18) ||
    (((buffer[tcphdr_len] & 0x7f) << 8 | buffer[tcphdr_len + 1]) > 9 )) &&
    (buffer[tcphdr_len+3] == 0x00) &&
    (buffer[tcphdr_len+4] == 0x02)) ||
    finding_TLS != 0)
    {

//        printf("in if %02x ", buffer[tcphdr_len ] & 0xff);
//        printf("in if %02x\n", buffer[tcphdr_len +1] & 0xff);
//        //https://stackoverflow.com/questions/3897883/how-to-detect-an-incoming-ssl-https-handshake-ssl-wire-format
        if (buffer[tcphdr_len] == 0x16 && buffer[tcphdr_len+5] == 0x01 && ntohs(tcph->th_sport) != 443) { //Handshake type Client-Hello SSLv3<
//            printf("som tu aspon raz?");
            char *temp_SNI = NULL;
            temp_SNI = get_TLS_SNI(buffer, tcphdr_len);
            if (!temp_SNI) {
                strcpy(header.sni, "Could not find SNI");
            }
            else {
                strcpy(header.sni, temp_SNI);
                free(temp_SNI);
            }
            header.ssl_ver = 1;
            header.packets = 1;
            uint32_t length = *(uint32_t *)(&buffer[tcphdr_len + 3]);
            header.size = ntohs(length); //test it pls
            header.size += loop_packet(buffer, tcphdr_len, data_len, false);
            DLInsertLast(&connection_list, header, ntohs(tcph->th_sport));
        }
        else if ((buffer[tcphdr_len+3] == 0x00) && (buffer[tcphdr_len+4] == 0x02) &&
         buffer[tcphdr_len+2] == 0x01) { //handshake Client-Hello SSLv2
            header.ssl_ver = 0;
            header.packets = 1;
            header.size = ((buffer[tcphdr_len] & 0x7f) << 8 | buffer[tcphdr_len + 1]); //ntohs(buffer[]); //test it pls
            strcpy(header.sni, "SSLv2 no SNI provided");
            DLInsertLast(&connection_list, header, ntohs(tcph->th_sport));
        } else {
//    	    printf("test portu %d\n", ntohs(tcph->th_sport));
    	    for (DLFirst(&connection_list); connection_list.Act != NULL; DLSucc(&connection_list)){
                if (connection_list.Act->port == ntohs(tcph->th_sport) || connection_list.Act->port == ntohs(tcph->th_dport)) {
                    connection_list.Act->data.end_time = time;
                    connection_list.Act->data.end_microsec = microsec;
                    connection_list.Act->data.packets += 1;
                    if (connection_list.Act->data.ssl_ver == 1) {
                        uint32_t length = *(uint32_t *) (&buffer[tcphdr_len + 3]);
                        connection_list.Act->data.size += ntohs(length); // add bytes to all data transfered
                        if (finding_TLS != 0)
                            connection_list.Act->data.size += finding_TLS;
                        else
                            connection_list.Act->data.size += loop_packet(buffer, tcphdr_len, data_len, false);

                    } else {
                        connection_list.Act->data.size += ((buffer[tcphdr_len] & 0x7f) << 8 | buffer[tcphdr_len + 1]);  //SSLv2
                    }
                    break;
                }
    	    }
//            printf("connection print SIZE: %d, PACKETS: %d time: %ld.%ld\n", connection_list.Act->data.size, connection_list.Act->data.packets, time, microsec);
    	}
    }
    if (tcph->th_flags & TH_FIN ) {
        DLFirst(&connection_list);
        for (;;){
            if (!connection_list.Act) break; // no connection in list yet, or we went through the list
            if (connection_list.Act->port == ntohs(tcph->th_sport) || connection_list.Act->port == ntohs(tcph->th_dport)) {
                long duration_sec = connection_list.Act->data.end_time - connection_list.Act->data.start_time;
                long duration_usec = connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
                if (duration_usec < 0) {
                    duration_usec = 1000000 + connection_list.Act->data.end_microsec - connection_list.Act->data.start_microsec;
                    duration_sec -= 1; //i use the second for micro seconds
                }
                char datetime[50];
                strftime(datetime,sizeof(datetime),"%Y-%m-%d %H:%M:%S", localtime(&connection_list.Act->data.start_time));
                printf("%s.%06ld,%s,%u,%s,%d,%s,%d,%ld.%06ld\n\n", datetime, connection_list.Act->data.start_microsec,
                       connection_list.Act->data.src_addr,connection_list.Act->data.src_port,connection_list.Act->data.dest_addr,
                       connection_list.Act->data.size,connection_list.Act->data.sni ,connection_list.Act->data.packets, duration_sec, duration_usec);
                if (connection_list.First == connection_list.Act) {
                    DLDeleteFirst(&connection_list);
                } else {
                    DLPred(&connection_list);
                    DLPostDelete(&connection_list);
                }
                break;

            }
            DLSucc(&connection_list);
        }
    }

    // strcpy(header.src_addr, temp_src);
    // strcpy(header.dest_addr, temp_dest);
    // free(temp_src);
    // free(temp_dest);
    // header.src_port = ntohs(tcph->th_sport);
    // header.dest_port = ntohs(tcph->th_dport);
    // header.header_size = tcphdr_len;
    // return header;
}



/*
*	Gets the whole packet, calls functions for packet parsing
* 	depending of protocol type
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
//	struct pckt_info packet_info;	// to save values for printing the data
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);
	char time[50];
	strftime(time,sizeof(time),"%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));

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
	switch (tcp_switch) //Check the Protocol and do accordingly...
	{
		case 6:  //TCP Protocol
			tcp_packet(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, buffer, ipv6, data_len);
			break;
	}
//	if (packet_info.header_size == -1){ // internal error
//		exit(20);		 	 			//something went wrong (malloc, etc)
//	}
//	print_data(time, pkthdr->ts.tv_usec, packet_info, data_len, data);
}


pcap_t *set_up(int mode,char *iface,char *rfile)
{
	struct bpf_program fp;        // to hold compiled program
    char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	bpf_u_int32 pMask;            // subnet mask 
	bpf_u_int32 pNet;             // ip address
    pcap_t *sniff;

    // fetch the network address and network mask
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
	char *iface = malloc(21 * sizeof(char));	//interface
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

	if (args != 10) {
		free(iface);
	}
	else {
		free(rfile);
	}
	return 0;
}