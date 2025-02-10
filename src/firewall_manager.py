import subprocess
import time
import logging

LOG_FILE = "/var/log/avenger_firewall.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

BAN_TIME = 600  # 10 минут
banned_ips = {}

class FirewallManager:
    def ban_ip(self, ip):
        """ Блокирует IP через iptables """
        if ip in banned_ips:
            return  # IP уже в бане
        
        command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(command)
        banned_ips[ip] = time.time()
        logging.warning(f"🔒 IP {ip} заблокирован!")

    def unban_expired_ips(self):
        """ Разблокирует IP через 10 минут """
        current_time = time.time()
        for ip in list(banned_ips.keys()):
            if current_time - banned_ips[ip] >= BAN_TIME:
                command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(command)
                del banned_ips[ip]
                logging.info(f"✅ IP {ip} разблокирован!")

if __name__ == "__main__":
    manager = FirewallManager()
    while True:
        manager.unban_expired_ips()
        time.sleep(60)  # Проверяем раз в минуту
