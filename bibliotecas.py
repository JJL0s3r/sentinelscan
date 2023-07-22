import subprocess
import importlib

# Lista de bibliotecas que você deseja instalar
libraries = [
    'socket',
    'pyfiglet',
    'requests',
    'whois',
    'beautifulsoup4',
    'importlib',
    'subprocess'
]

# Função para instalar ou verificar se a biblioteca está instalada
def install_or_check_library(library):
    try:
        importlib.import_module(library)
        print(f"Biblioteca '{library}' já está instalada!")
    except ImportError:
        try:
            print(f"Instalando {library}...")
            subprocess.check_call(['pip', 'install', library])
            print(f"{library} instalado com sucesso!")
        except Exception as e:
            print(f"Erro ao instalar {library}: {e}")

# Instalação ou verificação das bibliotecas
def install_libraries():
    for library in libraries:
        install_or_check_library(library)

if __name__ == "__main__":
    install_libraries()
    print("Todas as bibliotecas foram instaladas ou já estavam instaladas!")
