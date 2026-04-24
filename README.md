# Magneto

**Sistema web completo para geração automática de topologias de rede L1, L2 e L3 no formato draw.io.**

---

## 📋 Índice
- [Pré-requisitos](#pré-requisitos)
- [Como rodar localmente](#como-rodar-localmente)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Vantagens de rodar localmente](#vantagens-de-rodar-localmente)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Troubleshooting](#troubleshooting)
- [Contribuição](#contribuição)
- [Licença](#licença)

---

## 🔧 Pré-requisitos

Antes de começar, certifique-se de ter instalado:

- **[Node.js](https://nodejs.org/)** versão 18 ou superior
- **npm** (geralmente vem com Node.js) ou **yarn**
- **Git** (opcional, para clonar o repositório)
- Acesso SSH a equipamentos de rede (para extração de dados)

---

## 🚀 Como rodar localmente

### Instalação

1. **Clone ou extraia o projeto:**
   ```bash
   # Se usando Git
   git clone https://github.com/chpsilva02/Magneto.git
   cd Magneto
   
   # Ou extraia o arquivo ZIP na pasta desejada
   cd caminho/para/a/pasta/do/projeto
   ```

2. **Instale as dependências:**
   ```bash
   npm install
   ```

3. **Inicie o servidor de desenvolvimento:**
   ```bash
   npm run dev
   ```

4. **Acesse a aplicação:**
   Abra seu navegador e navegue até:
   ```
   http://localhost:3000
   ```

### Configuração

Se você precisa conectar a equipamentos de rede via SSH, configure suas credenciais no arquivo de configuração ou através das variáveis de ambiente:

```bash
# Exemplo (criar arquivo .env na raiz do projeto)
SSH_USER=seu_usuario
SSH_PASSWORD=sua_senha
SSH_KEY_PATH=/caminho/para/chave/privada
```

---

## 💡 Vantagens de rodar localmente

Como o sistema utiliza **conexões SSH reais** para extrair dados dos equipamentos, rodar o Magneto na sua máquina (ou em um servidor na sua rede interna) oferece:

✅ **Acesso a IPs privados:** Alcança equipamentos na sua rede interna  
✅ **Sem limitações de conectividade:** Não depende de hospedagem em nuvem  
✅ **Segurança:** Dados sensíveis permanecem na sua infraestrutura  
✅ **Melhor performance:** Processamento mais rápido para redes grandes  

**Nota:** Quando hospedado na nuvem, o sistema só consegue alcançar IPs públicos.

---

## 🛠️ Tecnologias Utilizadas

| Categoria | Tecnologia |
|-----------|-----------|
| **Backend** | Node.js, Express, SSH2 |
| **Frontend** | React, Tailwind CSS, Lucide Icons |
| **Processamento** | Dagre (Layout Matemático), XMLBuilder2 (Geração Draw.io) |

---

## 🐛 Troubleshooting

### Problema: Porta 3000 já está em uso
```bash
# Use uma porta diferente
PORT=3001 npm run dev
```

### Problema: Erro de conexão SSH
- Verifique credenciais SSH
- Confirme que os IPs/hosts estão acessíveis
- Verifique firewalls e regras de acesso

### Problema: Dependências não instaladas
```bash
# Limpe o cache do npm e reinstale
rm -rf node_modules package-lock.json
npm install
```

---

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Adiciona MinhaFeature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

---

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

---

**Dúvidas?** Abra uma [issue](https://github.com/chpsilva02/Magneto/issues) ou entre em contato com o mantenedor.