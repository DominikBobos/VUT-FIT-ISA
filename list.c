/* EDITED FOR ISA PROJECT PURPOSES 
 * BY Dominik Boboš (xbobos00)
 * File for ssl-sniffer.c implementing the list

 * ORIGINALLY FROM IAL course:
 * Předmět: Algoritmy (IAL) - FIT VUT v Brně
 * Soubor c206.c (Dvousměrně vázaný lineární seznam)
 * Vytvořil: Martin Tuček, září 2005
 * Upravil: Kamil Jeřábek, září 2019
 */

#include "sslsniff.h"

    

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

void DLInsertLast(tDLList *L, conn_info val, unsigned long port) {
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
