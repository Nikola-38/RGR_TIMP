from flask import Flask, render_template, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
import os
import json
import logging
import ipaddress

from flask_wtf import CSRFProtect
from scanner import scan_ports, scan_network_verbose
from analyzer import analyze_vulnerabilities
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from flask_wtf.csrf import CSRFProtect
from forms import RegistrationForm, LoginForm, ScanForm
app = Flask(__name__)

csrf = CSRFProtect(app)  # Включает CSRF для всех форм
pdfmetrics.registerFont(TTFont('DejaVuSans', 'fonts/DejaVuSans.ttf'))

load_dotenv()  # загружает из .env
app.secret_key = os.environ.get('SECRET_KEY')



# Настройка логирования в самом начале
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log'),
        logging.StreamHandler()
    ]
)

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Сначала войдите в систему.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')




USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_users(users):
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=4)
    except Exception as e:
        logging.error(f"Ошибка при сохранении пользователей: {e}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        users = load_users()

        username = form.username.data
        email = form.email.data
        password = form.password.data

        if username in users:
            flash("Пользователь с таким именем уже существует.")
            return render_template('register.html', form=form)

        hashed_password = generate_password_hash(password)

        users[username] = {
            "email": email,
            "password": hashed_password
        }

        save_users(users)
        flash("Регистрация прошла успешно. Войдите в систему.")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data.strip()

        users = load_users()
        user_found = None

        for username, data in users.items():
            if data.get('email', '').strip().lower() == email:
                user_found = (username, data)
                break

        if user_found and check_password_hash(user_found[1]['password'], password):
            session['username'] = user_found[0]
            flash(f'Добро пожаловать, {user_found[0]}!')
            return redirect(url_for('index'))
        else:
            flash('Неверная почта или пароль.')
    
    # Если GET или форма невалидна — просто отображаем страницу с формой
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Вы вышли из системы.")
    return redirect(url_for('index'))


def get_local_ip_and_subnet():
    # Статически заданные значения для корректной работы в WSL
    local_ip = 
    subnet_mask = 
    logging.info(f"[СТАТИЧЕСКИЙ РЕЖИМ] Локальный IP: {local_ip}, Маска: {subnet_mask}")
    return local_ip, subnet_mask


def netmask_to_cidr(mask):
    return sum([bin(int(x)).count('1') for x in mask.split('.')])


@app.route('/scan', methods=['POST'])
@login_required
def scan():
    form = ScanForm()

    if form.validate_on_submit():
        target_ip = form.ip_address.data

        # Проверка валидности IP с помощью ipaddress
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            flash("Неверный IP-адрес.")
            return redirect(url_for('index'))

        open_ports = scan_ports(target_ip)
        vulnerabilities = analyze_vulnerabilities(open_ports)

        return render_template(
            'index.html',
            open_ports=open_ports,
            vulnerabilities=vulnerabilities,
            scanned_ip=target_ip,
            form=form
        )
    else:
        flash('Неверный IP или ошибка формы')
        return redirect(url_for('index'))


@app.route('/scan_network')
@login_required
def scan_network_page():
    
    local_ip, subnet_mask = get_local_ip_and_subnet()

    logging.info(f"Локальный IP: {local_ip}, Маска подсети: {subnet_mask}")

    cidr = netmask_to_cidr(subnet_mask)
    subnet = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)

    active_devices, devices_status = scan_network_verbose(subnet)

    devices_info = []
    for device in active_devices:
        ports = scan_ports(device)
        devices_info.append({
            'ip': device,
            'ports': ports if ports else [],
            'status': devices_status[device]
        })

    # Создаём PDF-отчёт после сбора информации
    write_report_pdf(devices_info)

    return render_template('scan_network.html', devices=devices_info)


    stop_scan_flag = threading.Event()


port_names = {
                7: 'Echo',
                20: 'FTP-data',
                21: 'FTP',
                22: 'SSH-SCP',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                69: 'TFTP',
                80: 'HTTP',
                88: 'Kerberos',
                102: 'Iso-tsap',
                110: 'POP3',
                135: 'Microsoft EPMAP',
                137: 'NetBIOS-ns',
                139: 'NetBIOS-ssn',
                143: 'IMAP4',
                381: 'HP Openview',
                383: 'HP Openview',
                443: 'HTTP over SSL',
                445: 'SMB',
                464: 'Kerberos',
                465: 'SMTP over TLS/SSL, SSM',
                587: 'SMTP',
                593: 'Microsoft DCOM',
                636: 'LDAP over TLS/SSL',
                691: 'MS Exchange',
                902: 'VMware Server',
                989: 'FTP over SSL',
                990: 'FTP over SSL',
                993: 'IMAP4 over SSL',
                995: 'POP3 over SSL',
                1025: 'Microsoft RPC',
                1194: 'OpenVPN',
                1337: 'WASTE',
                1589: 'Cisco VQP',
                1725: 'Steam',
                2082: 'cPanel',
                2083: 'radsec, cPanel',
                2483: 'Oracle DB',
                2484: 'Oracle DB',
                2967: 'Symantec AV',
                3074: 'XBOX Live',
                3306: 'MySQL',
                3724: 'World of Warcraft',
                4664: 'Google Desktop',
                5432: 'PostgreSQL',
                5900: 'RFB/VNC Server',
                6665: 'IRC',
                6666: 'IRC',
                6667: 'IRC',
                6668: 'IRC',
                6669: 'IRC',
                6881: 'BitTorrent',
                6999: 'BitTorrent',
                6970: 'Quicktime',
                8086: 'Kaspersky AV',
                8087: 'Kaspersky AV',
                8222: 'VMware Server',
                9100: 'PDL',
                10000: 'BackupExec',
                12345: 'NetBus',
                27374: 'Sub7',
                31337: 'Back Orifice'
            }

def write_report_pdf(devices_info, filename="scan_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("DejaVuSans", 12)
    y = height - 40

    c.drawString(40, y, "Отчёт по сканированию сети")
    y -= 30

    for device in devices_info:
        if device['status'] == "Доступен" and device['ports']:
            c.drawString(40, y, f"IP: {device['ip']}")
            y -= 20

            c.drawString(60, y, "Открытые порты:")
            y -= 20

            for port in device['ports']:
                port_name = port_names.get(port, "Неизвестно")
                c.drawString(80, y, f"{port}: {port_name}")
                y -= 20

                # Проверка на переполнение страницы
                if y < 50:
                    c.showPage()
                    c.setFont("DejaVuSans", 12)
                    y = height - 40

            y -= 10  # немного отступа перед следующим устройством

    c.save()
    
if __name__ == "__main__":
    app.run(debug=True)
