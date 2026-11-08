SSH Bruteforce Parser
Opis projektu
Projekt został przygotowany w ramach laboratorium „Python cz. 3 – parser logów i IOC”.

Celem projektu jest analiza logów SSH w celu wykrywania wielu nieudanych prób logowania z tego samego adresu IP. Narzędzie identyfikuje potencjalne próby ataków typu brute force, zlicza nieudane logowania, generuje raporty oraz porównuje wykryte adresy IP z listą IOC (Indicators of Compromise).

Funkcjonalności
Program:

odczytuje plik logów SSH linia po linii,
wykorzystuje moduł pathlib do obsługi ścieżek,
sprawdza poprawność pliku wejściowego,
wykrywa wpisy zawierające komunikat Failed password,
wyciąga adresy IPv4 za pomocą wyrażeń regularnych,
zlicza liczbę nieudanych logowań dla każdego adresu IP,
sortuje wyniki malejąco według liczby prób,
oznacza adresy przekraczające ustalony próg alarmowy,
porównuje wykryte adresy z listą IOC,
generuje raport JSON,
generuje raport CSV,
obsługuje podstawowe błędy wejścia i parsowania.


Struktura projektu

log-parser-lab/

│

├── data/

│   ├── auth-sample.log

│   ├── apache-sample.log

│   └── ioc-ips.txt

│

├── output/

│   ├── ssh-bruteforce-summary.json

│   └── ssh-bruteforce-summary.csv

│

├── ssh_bruteforce_parser.py

├── README.md

└── requirements.txt



Wymagania
Python 3.10 lub nowszy.

Biblioteki standardowe:

pathlib
re
json
csv

Opcjonalnie:

pandas
numpy

Instalacja
Utworzenie środowiska wirtualnego:

Linux
python3 -m venv venv
source venv/bin/activate

Windows
python -m venv venv
venv\Scripts\activate

Instalacja zależności:

pip install -r requirements.txt

Uruchomienie
Przejdź do katalogu projektu:

cd log-parser-lab

Uruchom parser:

python ssh_bruteforce_parser.py

Działanie parsera
Parser analizuje plik:

data/auth-sample.log

Wyszukiwane są wpisy:

Failed password

Przykładowa linia:

Jan 10 10:00:01 server sshdFailed password for root from 192.168.1.10 port 22 ssh2

Za pomocą regex wyciągany jest adres IP:

r"from (\d+\.\d+\.\d+\.\d+)"

Następnie adresy są agregowane i sortowane według liczby wystąpień.

Próg alarmowy

Domyślny próg alarmowy:

ALERT_THRESHOLD = 3
Adres IP zostaje oznaczony jako alert, gdy liczba nieudanych prób logowania jest większa lub równa wartości progowej.

Przykład:

192.168.1.10 : 5 <-- ALERT
IOC (Indicators of Compromise)

Program odczytuje listę adresów IOC z pliku:

data/ioc-ips.txt

Przykład:

10.0.0.5
192.168.1.10
8.8.8.8

Każdy wykryty adres IP jest porównywany z listą IOC.

Dopasowanie oznacza jedynie sygnał analityczny i nie stanowi automatycznego potwierdzenia incydentu.


Raport JSON
Raport zapisywany jest do:

output/ssh-bruteforce-summary.json

Przykładowa zawartość:

{
    "file": "data/auth-sample.log",
    "alert_threshold": 3,
    "total_lines": 50,
    "failed_lines": 15,
    "skipped_lines": 35,
    "parsing_errors": 0,
    "alert_ips": [
        "192.168.1.10"
    ],
    "ioc_matches": [
        "192.168.1.10"
    ]
}

Raport CSV

Raport CSV zapisywany jest do:

output/ssh-bruteforce-summary.csv

Przykład:

source_ip,failed_logins,alert,ioc_match
192.168.1.10,5,True,True
10.0.0.5,2,False,False

Obsługa błędów

Program obsługuje:

nieistniejący plik,
podanie katalogu zamiast pliku,
błędy parsowania rekordów,
brak dopasowania regex,
pustą listę IOC.

Przykładowe komunikaty:

Błąd: plik nie istnieje.
Błąd: wskazana ścieżka nie jest plikiem.


Ograniczenia
Regex wykrywa kandydatów na adresy IPv4, ale nie wykonuje pełnej walidacji adresu.
Wykrycie wielu prób logowania nie oznacza automatycznie ataku.
Dopasowanie do IOC nie oznacza automatycznie potwierdzonego incydentu.
Projekt przeznaczony jest do celów edukacyjnych.


Przykładowy kod

Odczyt pliku przy użyciu pathlib
from pathlib import Path

log_path = Path("data/auth-sample.log")

with log_path.open("r", encoding="utf-8") as file:
    for line in file:
        print(line)

Filtrowanie nieudanych logowań SSH

if "Failed password" in line:
    failed_lines += 1


Przykładowa wykrywana linia:
Failed password for root from 192.168.1.10 port 22 ssh2


Ekstrakcja adresu IP przy użyciu regex

import re

pattern = r"from (\d+\.\d+\.\d+\.\d+)"

match = re.search(pattern, line)

if match:
    ip = match.group(1)

Dla wpisu:

Failed password for root from 192.168.1.10 port 22 ssh2

zostanie wyciągnięty adres:

192.168.1.10

Zliczanie prób logowania per IP
ip_counts[ip] = ip_counts.get(ip, 0) + 1

Przykładowy wynik:

{
    "192.168.1.10": 5,
    "10.0.0.5": 2
}

Sortowanie adresów IP

sorted_ips = sorted(
    ip_counts.items(),
    key=lambda item: item[1],
    reverse=True
)

Przykładowy wynik:

[
    ("192.168.1.10", 5),
    ("10.0.0.5", 2)
]
Oznaczanie adresów przekraczających próg alarmowy

ALERT_THRESHOLD = 3

if count >= ALERT_THRESHOLD:
    print(f"{ip}: {count} <-- ALERT")

Wczytywanie listy IOC

ioc_ips = set()

with open("data/ioc-ips.txt", "r") as file:
    for line in file:
        ip = line.strip()

        if ip:
            ioc_ips.add(ip)

Sprawdzanie dopasowań IOC

ioc_matches = []

for ip in ip_counts:

    if ip in ioc_ips:
        ioc_matches.append(ip)

Generowanie raportu JSON

report = {
    "file": str(log_path),
    "total_lines": line_count,
    "failed_lines": failed_lines,
    "ip_statistics": []
}

Zapis do pliku:

import json

with open(
    "output/ssh-bruteforce-summary.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=4,
        ensure_ascii=False
    )


Generowanie raportu CSV

import csv

with open(
    "output/ssh-bruteforce-summary.csv",
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow(
        ["source_ip", "failed_logins", "alert"]
    )

    for ip, count in sorted_ips:

        writer.writerow(
            [
                ip,
                count,
                count >= ALERT_THRESHOLD
            ]
        )


Przykładowy wynik działania


--- RAPORT ---

Przeanalizowane linie: 50
Dopasowane linie: 15
Pominięte linie: 35
Błędy parsowania: 0

TOP adresów IP:

192.168.1.10: 5 <-- ALERT
10.0.0.5: 4 <-- ALERT
172.16.1.20: 1

IOC MATCHES:

192.168.1.10