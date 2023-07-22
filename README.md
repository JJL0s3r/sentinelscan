Passo 1: Requisitos para usar o Sentinel Scan
Antes de executar o Sentinel Scan, verifique se você possui os seguintes requisitos em sua máquina:

Python: O Sentinel Scan é um script Python, portanto, você precisará ter o Python instalado em sua máquina. O código foi escrito para o Python 3.x, então certifique-se de usar uma versão recente do Python 3.

Pacote pip: O pip é o gerenciador de pacotes do Python e geralmente é instalado automaticamente junto com o Python. Verifique se você tem o pip instalado corretamente executando o seguinte comando no terminal ou prompt de comando:

bash
Copy code
pip --version
Acesso à Internet: O Sentinel Scan requer acesso à Internet para realizar as verificações de vulnerabilidade.
Passo 2: Clonando o repositório do Sentinel Scan
No terminal ou prompt de comando, execute o seguinte comando para clonar o repositório do Sentinel Scan do GitHub:

bash
Copy code
git clone https://github.com/JJL0s3r/sentinelscan
Passo 3: Instalando as bibliotecas necessárias
Após clonar o repositório, acesse o diretório do Sentinel Scan:

bash
Copy code
cd sentinelscan
No diretório do Sentinel Scan, há um arquivo chamado bibliotecas.py. Este arquivo contém o script que instala as bibliotecas necessárias para o funcionamento do Sentinel Scan.

Para executar o script e instalar as bibliotecas, execute o seguinte comando:

bash
Copy code
python bibliotecas.py
Este script verificará se as bibliotecas necessárias estão instaladas em sua máquina e, se não estiverem, as instalará automaticamente.

Passo 4: Executando o Sentinel Scan
Depois de ter as bibliotecas instaladas, você pode executar o Sentinel Scan. Para isso, utilize o seguinte comando:

bash
Copy code
python sentinelscan.py
O Sentinel Scan será iniciado e realizará uma varredura em busca de vulnerabilidades em seu sistema. Certifique-se de fornecer as informações necessárias solicitadas pelo script para que ele possa executar as verificações adequadas.

Observação: O Sentinel Scan é uma ferramenta de segurança e, portanto, deve ser usado com responsabilidade. Verifique se você tem permissão para executar o scan em sistemas que não sejam de sua propriedade e nunca utilize essa ferramenta para fins maliciosos.
