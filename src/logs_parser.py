import re

class LogsParser:
    def __init__(self, log_files):
        self.log_files = log_files
        self.iptables_pattern = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+)")

    def parse_logs(self):
        suspicious_ips = set()
        for log_file in self.log_files:
            try:
                with open(log_file, "r") as file:
                    for line in file:
                        match = self.iptables_pattern.search(line)
                        if match:
                            ip = match.group(1)
                            suspicious_ips.add(ip)
            except FileNotFoundError:
                print(f"⚠️ Лог-файл {log_file} не найден!")

        return suspicious_ips
