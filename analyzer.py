def analyze_vulnerabilities(open_ports):
    # Пример проверки на уязвимости (можно расширить)
    vulnerabilities = {}
    known_vulnerabilities = {
        21: "FTP - Используйте FTPS или отключите FTP, если не используется.",
        22: "SSH - Проверьте, включена ли аутентификация по паролю.",
        23: "Telnet - Не используйте Telnet, замените на SSH.",
        25: "SMTP - Убедитесь, что используется защита от спама и TLS.",
        80: "HTTP - Убедитесь, что используется HTTPS.",
        110: "POP3 - Используйте POP3S или переходите на более защищённые протоколы.",
        143: "IMAP - Убедитесь, что используется IMAPS.",
        443: "HTTPS - Проверьте сертификаты безопасности.",
        3306: "MySQL - Проверьте настройки аутентификации и сетевой доступ.",
        3389: "RDP - Используйте VPN и двухфакторную аутентификацию.",
    }
    for port in open_ports:
        if port in known_vulnerabilities:
            vulnerabilities[port] = known_vulnerabilities[port]
    return vulnerabilities

