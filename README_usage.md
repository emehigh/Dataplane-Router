###############################################################################
###############################################################################
###############################################################################

    Tema 1 Protocoale de comunicatii - router

###############################################################################
###############################################################################

    In aceasta tema am implementat functionalitatea unui router in felul urmator:
        - verific ce fel de pachet am primit(ipv4 / arp)
            - daca e ipv4 si am adresa mac la care trebuie sa dau forward, pur si simlpu il trimit mai departe;
                daca nu, fac un arp request broadcast pentru a afla adresa mac de care am nevoie si pun pachetul   
                intr-un queue pentru a-l trimit mai tarziu.
            - daca e arp_request, trimit inapoi adresa mea mac(a routerului) de unde a venit request-ul; daca
                e arp reply, verific daca nu cumva vreunul din pachetele mele din queue poate folosi adresa 
                mac, iar in acest caz, trimit pachetul unde trebuia sa ajunga.
            
###############################################################################
###############################################################################
###############################################################################

    Paraschiva Mihai Eugeniu - 322CC

###############################################################################
###############################################################################
