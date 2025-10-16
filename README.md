⚙️ Fonctionnalités principales

📡 Capture directe du trafic brut à l’aide de socket.AF_PACKET

🔍 Analyse des en-têtes Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP

🌐 Détection des requêtes DNS (UDP/TCP) et affichage du nom de domaine demandé

🧩 Association Processus ↔ Connexion via /proc/net/* et /proc/[pid]/fd/

💾 Export des logs au format CSV et JSON

🚀 Cache PID intelligent : détection incrémentale des nouveaux processus

🖥️ Interface CLI dynamique (type “nethogs”) rafraîchie en continu

🔐 Nécessite uniquement Python standard (aucune dépendance externe)

📋 Installation
1️⃣ Prérequis

    Système : Linux

    Python : 3.8+

    Droits administrateur (capture de paquets brute)

2️⃣ Cloner ou copier le script

" git clone https://github.com/votreuser/network-process-monitor
 cd network-process-monitor "

3️⃣ Exécuter le programme

" sudo python3 net_monitor.py "


⚠️ L’utilisation de sudo est obligatoire car le socket brut (AF_PACKET) nécessite des privilèges root.

# Fonctionnement interne

1️⃣ Capture du trafic

    Le script crée un socket brut :

" socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) "

Cela permet de recevoir tous les paquets réseau avant traitement par le noyau.

2️⃣ Cloner ou copier le script

    Chaque paquet est décodé manuellement :

     Ethernet → Extraction de la couche réseau (IPv4, IPv6, ARP)

     IPv4 / IPv6 → Analyse des adresses source/destination

     TCP / UDP / ICMP → Lecture des ports et codes

     DNS → Décodage basique pour extraire le nom de domaine (QNAME)

    Aucun module externe n’est utilisé (tous les parsers sont faits avec struct.unpack).



3️⃣ Association avec les processus

L’outil parcourt /proc/net/tcp, /proc/net/udp, /proc/net/raw, etc.
et associe chaque socket inode à un PID via les liens symboliques contenus dans /proc/[pid]/fd/.

Un cache incrémental est maintenu pour éviter un rechargement complet à chaque rafraîchissement :

    Nouvelles connexions → ajoutées

    PIDs terminés → retirés du cache


4️⃣ Affichage et export

    L’affichage se fait en CLI dynamique (rafraîchissement toutes les secondes)

    Les colonnes principales sont :
    | Time | Protocol | Src IP | Dst IP | Src Port | Dst Port | Process | Info |

    Si le trafic DNS est détecté, la colonne Info contient le nom de domaine demandé.

    En parallèle, les événements sont exportés :

 #   network_log.json

 #   network_log.csv

📁 Exemple de sortie
 ┌─────────────────────────────────────────────────────────────┐
 │ Time       Proto  Src IP         Dst IP        Process  Info│
 ├─────────────────────────────────────────────────────────────┤
 │ 10:15:23   TCP    192.168.1.5 → 142.250.74.238  firefox 443 │
 │ 10:15:23   DNS    192.168.1.5 → 8.8.8.8        systemd  www.google.com │
 │ 10:15:24   UDP    192.168.1.5 → 224.0.0.251    avahi    mDNS │
 └─────────────────────────────────────────────────────────────┘


🧩 Options de personnalisation (facultatives)

Tu peux modifier dans le code :

La fréquence de rafraîchissement (REFRESH_INTERVAL = 1.0)

Le niveau de verbosité (affichage brut ou résumé)

Les fichiers d’export (network_log.csv, network_log.json)


⚠️ Limitations

Ne fonctionne que sur Linux (utilisation de /proc et AF_PACKET)

Nécessite sudo pour accéder au trafic bas niveau

Ne capture pas le trafic crypté (HTTPS) — seules les métadonnées (IP/port) sont visibles


# 🚀 Exemple d’utilisation avancée

Exécuter et rediriger la sortie dans un fichier log :

# " sudo python3 monitor.py | tee live_network.log "

Filtrer un protocole spécifique (ex. DNS uniquement) :

" sudo python3 monitor.py --filter dns "
