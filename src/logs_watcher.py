import time
import os
import re
import logging
from firewall_manager import FirewallManager

# Лог-файл для записей (лучше, чем спам в консоль)
LOG_FILE = "/var/log/avenger_firewall.log"

# Конфигурируем логгер
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Пути к лог-файлам для анализа
LOG_FILES = ["/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/iptables.log"]

# Регулярки для поиска атак
FAILED_LOGIN_PATTERN = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
DDOS_PATTERN = r"(\d+\.\d+\.\d+\.\d+) - - .*\"GET /.* HTTP/1.1\" 200"

# Лимит попыток перед баном
THRESHOLD = 5

class LogsWatcher:
    def __init__(self, log_files):
        self.log_files = log_files
        self.firewall = FirewallManager()
        self.ip_attempts = {}  # Подсчет попыток по IP

    def check_logs(self):
        """ Читаем логи и ищем атаки """
        for log_file in self.log_files:
            if not os.path.exists(log_file):
                logging.warning(f"Лог-файл {log_file} не найден!")
                continue

            with open(log_file, "r") as file:
                for line in file:
                    self.process_log_line(line)

    def process_log_line(self, line):
        """ Проверяем строку лога на атаки """
        failed_match = re.search(FAILED_LOGIN_PATTERN, line)
        if failed_match:
            ip = failed_match.group(1)
            self.track_ip(ip)

        ddos_match = re.search(DDOS_PATTERN, line)
        if ddos_match:
            ip = ddos_match.group(1)
            self.track_ip(ip)

    def track_ip(self, ip):
        """ Учитываем попытки атаки и баним при превышении порога """
        self.ip_attempts[ip] = self.ip_attempts.get(ip, 0) + 1
        logging.info(f"Обнаружена активность с IP: {ip} ({self.ip_attempts[ip]} попыток)")

        if self.ip_attempts[ip] >= THRESHOLD:
            logging.warning(f"🚨 IP {ip} превысил лимит! Блокируем!")
            self.firewall.ban_ip(ip)

    def watch_logs(self):
        """ Основной цикл мониторинга логов """
        logging.info("🚀 Мониторинг логов запущен...")
        while True:
            self.check_logs()
            self.firewall.unban_expired_ips()
            time.sleep(10)

if __name__ == "__main__":
    watcher = LogsWatcher(LOG_FILES)
    watcher.watch_logs()
