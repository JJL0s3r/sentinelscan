# Sentinel Scan

O Sentinel Scan é uma ferramenta de varredura de vulnerabilidades desenvolvida em Python. Ele verifica sistemas em busca de vulnerabilidades conhecidas e ajuda a identificar possíveis problemas de segurança.

## Requisitos para usar o Sentinel Scan

Antes de executar o Sentinel Scan, verifique se você possui os seguintes requisitos em sua máquina:

1. Python: O Sentinel Scan é um script Python, portanto, você precisará ter o Python instalado em sua máquina. Se você ainda não tem o Python instalado, você pode baixá-lo em [python.org](https://www.python.org/downloads/) e seguir as instruções de instalação para o seu sistema operacional.

2. Pacote `pip`: O `pip` é o gerenciador de pacotes do Python e geralmente é instalado automaticamente junto com o Python. Se o `pip` não estiver instalado, você pode baixá-lo e instalá-lo seguindo o guia oficial [aqui](https://pip.pypa.io/en/stable/installing/).

3. Acesso à Internet: O Sentinel Scan requer acesso à Internet para realizar as verificações de vulnerabilidade.

## Como usar o Sentinel Scan

Abra o terminal de seu computador e siga os passos abaixo para executar o Sentinel Scan em sua máquina:

1. Clone o repositório do Sentinel Scan do GitHub:

`git clone https://github.com/JJL0s3r/sentinelscan`

2. Acesse o diretório do Sentinel Scan:

`cd sentinelscan`

3. Instale as bibliotecas necessárias executando o seguinte comando:

`python bibliotecas.py` ou `python3 bibliotecas.py`


O script `bibliotecas.py` verificará se as bibliotecas necessárias estão instaladas em sua máquina e, se não estiverem, as instalará automaticamente.

4. Execute o Sentinel Scan com o seguinte comando:

`python SentinelScan.py` ou `python3 SentinelScan.py`


O Sentinel Scan será iniciado e realizará uma varredura em busca de vulnerabilidades em seu sistema. Certifique-se de fornecer as informações necessárias solicitadas pelo script para que ele possa executar as verificações adequadas.

## ERRO NO WHOIS

Caso você for fazer uma consulta WHOIS pelo Sentinel Scan pela sua maquina e ele der o seguinte erro ou algo parecido:

Traceback (most recent call last):

  File "C:\Users\[NOME DO SEU USER]\sentinelscan\SentinelScan.py", line 105, in perform_whois
    domain = whois.whois(url)
             ^^^^^^^^^^^
AttributeError: module 'whois' has no attribute 'whois'
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
  File "C:\Users\[NOME DO SEU USER]\sentinelscan\SentinelScan.py", line 331, in <module>
    perform_whois(url)
  File "C:\Users\[NOME DO SEU USER]\sentinelscan\SentinelScan.py", line 127, in perform_whois
    except whois.parser.PywhoisError as e:
           ^^^^^^^^^^^^
AttributeError: module 'whois' has no attribute 'parser'

Caso ele dê esse erro ou algo parecido, siga os seguintes passos:
1. Desinstale a versão atual, execute o seguinte comando em seu terminal ou prompt de comando:

`pip uninstall python-whois` (ou) `pip uninstall whois` (ou a versão da biblioteca WHOIS que estiver instalada em sua maquina)

3. Instale outra versão da biblioteca WHOIS:

`pip install python-whois==0.7.3`

(CASO O ERRO AO FAZER UMA CONSULTA WHOIS PELO SENTINEL SCAN PERSISTA, FAVOR ENTRAR EM CONTATO: (d.aaraujo.ti@gmail.com))
## Aviso

O Sentinel Scan é uma ferramenta de segurança e, portanto, deve ser usada com responsabilidade. Verifique se você tem permissão para executar o scan em sistemas que não sejam de sua propriedade e nunca utilize essa ferramenta para fins maliciosos.

## Contribuição

Se você quiser contribuir com o Sentinel Scan ou relatar problemas, sinta-se à vontade para abrir uma issue ou enviar um pull request para o repositório. (d.aaraujo.ti@gmail.com)

## Licença

Este projeto é licenciado sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para obter mais detalhes.
