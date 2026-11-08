from pathlib import Path
import re
import json
import csv
import pandas as pd

# ==========================================
# KONFIGURACJA
# ==========================================

log_path = Path("data/auth-sample.log")
ioc_path = Path("data/ioc-ips.txt")

ALERT_THRESHOLD = 3

# ==========================================
# WALIDACJA PLIKU
# ==========================================

if not log_path.exists():
    print(f"Błąd: plik {log_path} nie istnieje.")
    exit()

if not log_path.is_file():
    print(f"Błąd: {log_path} nie jest plikiem.")
    exit()

# ==========================================
# ZMIENNE
# ==========================================

pattern = r"from (\d+\.\d+\.\d+\.\d+)"

line_count = 0
failed_lines = 0
skipped_lines = 0
parsing_errors = 0

ip_counts = {}

# ==========================================
# ANALIZA LOGU
# ==========================================

try:

    with log_path.open("r", encoding="utf-8") as file:

        for line in file:

            line_count += 1

            if "Failed password" in line:

                failed_lines += 1

                match = re.search(pattern, line)

                if match:

                    ip = match.group(1)

                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

                else:
                    parsing_errors += 1

            else:
                skipped_lines += 1

except Exception as e:
    print(f"Wystąpił błąd podczas odczytu pliku: {e}")
    exit()

# ==========================================
# SORTOWANIE
# ==========================================

sorted_ips = sorted(
    ip_counts.items(),
    key=lambda item: item[1],
    reverse=True
)

# ==========================================
# ALERTY
# ==========================================

alert_ips = []

for ip, count in sorted_ips:

    if count >= ALERT_THRESHOLD:
        alert_ips.append(ip)

# ==========================================
# WCZYTANIE IOC
# ==========================================

ioc_ips = set()

if ioc_path.exists():

    with ioc_path.open("r", encoding="utf-8") as file:

        for line in file:

            ip = line.strip()

            if ip:
                ioc_ips.add(ip)

ioc_matches = []

for ip in ip_counts:

    if ip in ioc_ips:
        ioc_matches.append(ip)

# ==========================================
# RAPORT NA EKRAN
# ==========================================

print("\n--- RAPORT ---")

print(f"Przeanalizowane linie: {line_count}")
print(f"Dopasowane linie: {failed_lines}")
print(f"Pominięte linie: {skipped_lines}")
print(f"Błędy parsowania: {parsing_errors}")

print("\nAdresy IP:")

for ip, count in ip_counts.items():
    print(f"{ip}: {count}")

print("\nTOP adresów IP:")

for ip, count in sorted_ips:

    if count >= ALERT_THRESHOLD:
        print(f"{ip}: {count} <-- ALERT")
    else:
        print(f"{ip}: {count}")

print("\nIOC MATCHES:")

if ioc_matches:

    for ip in ioc_matches:
        print(ip)

else:
    print("Brak dopasowań IOC")

# ==========================================
# RAPORT JSON
# ==========================================

report = {
    "file": str(log_path),
    "alert_threshold": ALERT_THRESHOLD,
    "total_lines": line_count,
    "failed_lines": failed_lines,
    "skipped_lines": skipped_lines,
    "parsing_errors": parsing_errors,
    "alert_ips": alert_ips,
    "ioc_matches": ioc_matches,
    "ip_statistics": [],
    "note": (
        "Wynik jest sygnałem analitycznym i nie stanowi "
        "automatycznego potwierdzenia incydentu."
    )
}

for ip, count in sorted_ips:

    report["ip_statistics"].append(
        {
            "source_ip": ip,
            "failed_logins": count,
            "alert": count >= ALERT_THRESHOLD,
            "ioc_match": ip in ioc_ips
        }
    )

json_file = Path(
    "output/ssh-bruteforce-summary.json"
)

with json_file.open(
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=4,
        ensure_ascii=False
    )

print(
    f"\nRaport JSON zapisano do: {json_file}"
)

# ==========================================
# RAPORT CSV
# ==========================================

csv_file = Path(
    "output/ssh-bruteforce-summary.csv"
)

with csv_file.open(
    "w",
    encoding="utf-8",
    newline=""
) as file:

    writer = csv.writer(file)

    writer.writerow(
        [
            "source_ip",
            "failed_logins",
            "alert",
            "ioc_match"
        ]
    )

    for ip, count in sorted_ips:

        writer.writerow(
            [
                ip,
                count,
                count >= ALERT_THRESHOLD,
                ip in ioc_ips
            ]
        )

print(
    f"Raport CSV zapisano do: {csv_file}"
)

#Dzialania w Pandas
df = pd.read_csv(
    "output/ssh-bruteforce-summary.csv"
)

print(df.head())

print(df.columns)

sorted_df = df.sort_values(
    by="failed_logins",
    ascending=False)
print(sorted_df)

top10 = sorted_df.head(10)
print(top10)

alerts = df[df["alert"] == True]
print(alerts)
alerts.to_csv(
    "output/alerts_only.csv",
    index=False
)

print(
"\nZapisano: output/alerts_only.csv"
)