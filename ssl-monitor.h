/* EDITED FOR ISA PROJECT PURPOSES 
 * BY Dominik Boboš (xbobos00)
 * Header file for ssl-sniffer.c 

 * ORIGINALLY FROM IAL course:
 * Předmět: Algoritmy (IAL) - FIT VUT v Brně
 * Hlavičkový soubor pro c206.c (Dvousměrně vázaný lineární seznam)
 * Vytvořil: Martin Tuček, září 2005
 * Upravil: Kamil Jeřábek, září 2019
 */

#include<stdio.h>
#include<stdlib.h>

/*
 *	Struct with info about the connection
 */
typedef struct pckt_info
{
    char src_addr[40];		//contains source IPv4/6 , 40 is the longest it could get 
    char dest_addr[40];		//contains destination IPv4/6  
    unsigned src_port;		//contains source  PORT
    char sni[1025];         //SNI - server name indication of max size 1024 characters
    long start_time;        //the timestamp of the first packet in connection (Client-Hello)
    long start_microsec;    //the same as above but the microseconds
    long end_time;          //the timestamp of the newest packet in connection
    long end_microsec;      //the same as above but the microseconds
    int packets;            //packets count in connection
    int size;               //data in Bytes transfered in connection
    int ssl_ver;            //0 for SSLv2 1 for SSLv3,TLSv1.0,1.1,1.2

} pckt_info;

/*
 * Pointer to element of the list
 */ 
typedef struct tDLElem {            
        int port;						/* key for finding the right connection */
    	struct pckt_info data;         	/* useful data */
        struct tDLElem *lptr;          	/* ptr to the previous element in the list */
        struct tDLElem *rptr;        	/* ptr to the next element in the list */
} *tDLElemPtr;
typedef struct {                        
    tDLElemPtr First;                   /* ptr to the first element of the list*/
    tDLElemPtr Act;                     /* ptr to the active element of the list */
    tDLElemPtr Last;                    /* ptr to the last element of the list */
} tDLList;

void DLInitList (tDLList *);
void DLDisposeList (tDLList *);
void DLInsertLast(tDLList *, pckt_info, int);
void DLFirst (tDLList *);
void DLDeleteFirst (tDLList *);
void DLDeleteLast (tDLList *);
void DLPostDelete (tDLList *);
void DLCopy (tDLList *, int *);
void DLActualize (tDLList *, int);
void DLSucc (tDLList *);
void DLPred (tDLList *);