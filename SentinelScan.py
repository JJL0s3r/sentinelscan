import socket
import pyfiglet
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import os
import time
import traceback
from urllib.parse import quote

text = "Sentinel  Scan"
font = pyfiglet.Figlet()

banner = font.renderText(text)
print(banner)


# Exibe os comandos disponíveis
def show_commands():
    print("Comandos disponíveis:\n")
    print("'ss' or 'sentinel scan' - Exibir tela inicial\n")
    print("'ss ip' - Obter o IP do servidor\n")
    print("'ss whois' - Realizar WHOIS\n")
    print("'ss -p' - Escanear todas as portas\n")
    print("'ss -x' - Verificar vulnerabilidade de XSS\n")
    print("'ss -s' - Verificar vulnerabilidade de SQL injection\n")
    print("'ss -i' - Verificar vulnerabilidade de IDOR\n")
    print("'ss -v' - Verificar se há vulnerabilidade XSS, IDOR e SQL injection\n")
    print("'info' - Mostrar informações sobre o programa\n")
    print("'clear' - Limpar a tela\n")
    print("'exit' - Sair\n\n\n")
    
    print("Se caso na hora de fazer o scan, der algum erro quando você informa a url, tente iniciar o script novamente e colocar sem 'http' ou 'https' ou adiciona-los\n")

show_commands()


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


    elif command == "clear":
        if os.name == "posix":
            os.system("clear")  # Limpa a tela no Linux/macOS
        else:
            os.system("cls")  # Limpa a tela no Windows
    
    elif command.startswith("ss"):
        if command == "ss -p":
            url = input("Digite a URL que deseja escanear: ")
            print("Escaneando todas as portas...")
            scan_ports(url, range(1, 65536))
        elif command.startswith("ss "):
            command_parts = command.split()

    

   
            
            
            if len(command_parts) >= 2:
                subcommand = command_parts[1]
                if subcommand.isdigit():
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
                else:
                    print("Comando inválido. Por favor, tente novamente.")
            else:
                print("Comando inválido. Por favor, tente novamente.")
                
            
                
    elif command == "exit":
        break
    else:
        print("Comando inválido. Por favor, tente novamente.")
