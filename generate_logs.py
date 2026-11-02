import random, datetime
with open("advanced_traffic.log", "w") as f:
    for i in range(480): # Normal traffic
        f.write(f'192.168.1.{random.randint(1,50)} - - [02/Nov/2026:12:00:00 +0530] "GET /index.html HTTP/1.1" 200 1024\n')
    for i in range(15): # Brute force attacker
        f.write(f'10.99.0.5 - - [02/Nov/2026:12:05:00 +0530] "POST /login HTTP/1.1" 401 512\n')
    for i in range(5): # SQL Injection attempts
        f.write(f'172.16.0.8 - - [02/Nov/2026:12:10:00 +0530] "GET /api?user=1%27%20OR%20%271%27=%271 HTTP/1.1" 403 256\n')