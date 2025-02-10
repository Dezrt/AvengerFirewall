import re

class LogsParser:
    def __init__(self, log_files):
        self.log_files = log_files

    def parse_logs(self):
        """Читает файлы логов и извлекает подозрительные IP-адреса."""
        suspicious_ips = {}

        ssh_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
        nginx_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+) .* HTTP/1.\d\" 40\d")
        
        for log_file in self.log_files:
            try:
                with open(log_file, "r", encoding="utf-8") as file:
                    for line in file:
                        ssh_match = ssh_pattern.search(line)
                        nginx_match = nginx_pattern.search(line)

                        if ssh_match:
                            ip = ssh_match.group(1)
                            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

                        if nginx_match:
                            ip = nginx_match.group(1)
                            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

            except FileNotFoundError:
                print(f"❌ Файл {log_file} не найден!")

        return {ip: count for ip, count in suspicious_ips.items() if count > 5}  # Только IP с 5+ попытками

if __name__ == "__main__":
    parser = LogsParser(["/var/log/auth.log", "/var/log/nginx/access.log"])
    bad_ips = parser.parse_logs()
    
    if bad_ips:
        print("⚠️ Подозрительные IP-адреса:", bad_ips)
    else:
        print("✅ Всё чисто, атак нет!")
