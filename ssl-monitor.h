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
#include<stdbool.h>

/*
 *	Struct with info about the connection
 */
typedef struct conn_info
{
    char src_addr[40];		//contains source IPv4/6 , 40 is the longest it could get 
    char dest_addr[40];		//contains destination IPv4/6  
    unsigned long src_port;		//contains source  PORT
    char sni[1025];         //SNI - server name indication of max size 1024 characters
    long start_time;        //the timestamp of the first packet in connection (TCP SYN)
    long start_microsec;    //the same as above but the microseconds
    int packets;            //packets count in connection from TCP SYN to TCP FIN
    int size;               //SSL data in Bytes transfered in connection
    bool has_ssl;           // to recognize from basic
    bool has_syn_ack;
    bool second_fin;

} conn_info;

/*
 * Pointer to element of the list
 */ 
typedef struct tDLElem {
        int port;						/* key for finding the right connection */
    	struct conn_info data;         	/* useful data */
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
void DLInsertLast(tDLList *, conn_info, unsigned long);
void DLFirst (tDLList *);
void DLDeleteFirst (tDLList *);
void DLPostDelete (tDLList *);
void DLSucc (tDLList *);
void DLPred (tDLList *);
