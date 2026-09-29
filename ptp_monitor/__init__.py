"""PTP Monitor — surveillance passive des horloges PTP sur réseaux AoIP.

Moniteur passif PTPv1 (Dante) et PTPv2 (AES67/Ravenna) pour le diagnostic
de problèmes d'horloge sur réseaux audio sur IP. N'émet aucun trafic PTP :
simple jointure IGMP au groupe multicast standard 224.0.1.129 (UDP 319/320).
"""

__version__ = "1.0.0"
