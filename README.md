# Magneto

Sistema web completo para geração automática de topologias de rede L1, L2 e L3 no formato draw.io.

## Pré-requisitos

Para rodar este projeto na sua máquina, você precisará ter instalado:
- **[Node.js](https://nodejs.org/)** (versão 18 ou superior)

## Como rodar localmente

1. Extraia o arquivo ZIP do projeto em uma pasta da sua preferência.
2. Abra o terminal (ou prompt de comando) e navegue até a pasta do projeto:
   ```bash
   cd caminho/para/a/pasta/do/projeto
   ```
3. Instale todas as dependências necessárias executando:
   ```bash
   npm install
   ```
4. Inicie o servidor de desenvolvimento:
   ```bash
   npm run dev
   ```
5. Abra o seu navegador e acesse:
   **http://localhost:3000**

## Vantagem de rodar localmente

Como o sistema utiliza conexões SSH reais para extrair os dados dos equipamentos, rodar o projeto na sua própria máquina (ou em um servidor na sua rede) permite que o Magneto acesse **IPs privados** (ex: `192.168.x.x`, `10.x.x.x`, `172.16.x.x`). 

Quando hospedado na nuvem, o sistema só consegue alcançar IPs públicos.

## Tecnologias Utilizadas
- **Backend:** Node.js, Express, SSH2
- **Frontend:** React, Tailwind CSS, Lucide Icons
- **Processamento:** Dagre (Layout Matemático), XMLBuilder2 (Geração do Draw.io)
