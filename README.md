| **Detection Method**           | **Description**                                                                                                                                              | **Pros**                                                           | **Cons**                                                             | **Progress** |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------|--------------|
| Unexpected Master Activity     | Monitor all masters. If a master becomes active (e.g., owns bus cycles) when not scheduled or expected, trigger a warning.                                   | Very generic. Catches many classes of trojans.                     | Needs basic knowledge of which master should be active normally.     | ❌           |
| Master+Sensitive Memory Access | When any master becomes active, watch if it accesses sensitive regions (e.g., 0x2000_0000 to 0x2000_0FFF). Trigger if suspicious reads occur.                | Covers many types of RAM snooping attacks.                         | If legit processes also access these areas, you must whitelist them. | ✅           |
| Arbiter Behavior Monitoring    | Check if a master unexpectedly wins arbitration when it shouldn't (e.g., lower-priority master wins when higher-priority still requests).                    | Very strong for bus attacks.                                       | Requires a slightly smarter Arbiter (with self-reporting of grants). | ❌           |
| Timing Anomalies               | Watch for unusual bus activity timing: e.g., masters suddenly bursting RAM reads outside of known busy windows (especially at weird times like system idle). | No need to know addresses. Catches side-channel style trojans too. | May require profiling normal system behavior.                        | ❌           |
| Address Access Profiling       | Learn typical address usage patterns. For example: Master A writes only to addresses X, Y, Z. Deviations → suspicious.                                       | Extremely strong. No false positives if well trained.              | Requires a learning phase (in training mode).                        | ✅           |
| Activity counters | Continuously count activity on the bus with a sample rate (number of write/read and compare to last sample) | Almost lightweight ? IDK but at least it is fun (? I guess ?). Who reads that after all ? | May require a learning phase to define thresholds. A very hidden trojan wouldn't be detected | ✅ |
| Activity counters with learning phase | Continuously count activity on the bus with a sample rate (number of write/read and compare to last sample) | The learning phase set the thresholds for us | Has a learning phase to define thresholds. A very hidden trojan would still not be detected | ... |
| Read/Write Behavior Profiling  | Masters typically write a lot (CPU, AES), but trojans tend to read keys a lot. Profiling read/write ratios per master can help.                              | Lightweight additional protection.                                 | May be fooled by trojans that mimic normal write/read patterns.      | ❌           |

Migen tutorial: (to create Modules)
https://m-labs.hk/docs/migen-tutorial.pdf
lots de fonctions caractérisées -> le cpu\
analyser le périmètre, dans quelle mesure on peut adapter ça pour des opérations non triviales (egs + de composants)\
Séparer en deux le module de détection. Voir s'il y a possibilté de détecter le nombre de masters. Séparer les contributions des masters.\
qui a eu le droit sur le bus de com. En gros, "Qui qui c'est qui communique avec la ram ?"

on a la main sur l'arbitre (et un peu de place à côté pour les détections)\
Reconfiguration partielle / dynamique partielle\
cible on est dans des entreprises qui remplacent leur automates
