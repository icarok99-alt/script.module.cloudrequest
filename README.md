# CloudRequest

**Versão:** 1.0.0  
**Desenvolvido por:** oneplay team

---

## Sobre

CloudRequest é uma biblioteca HTTP leve e poderosa para Kodi que fornece uma sessão **CloudScraper** com bypass automático do Cloudflare (incluindo o desafio IUAM - "I'm Under Attack Mode").

Permite que addons Kodi acessem sites protegidos pelo Cloudflare de forma transparente, sem interrupções ou bloqueios.

---

## Recursos

- Bypass automático de desafios Cloudflare IUAM
- Compatível com a API do `requests`
- Implementado 100% em Python
- Leve e otimizado para Kodi

---

## Como usar

```python
from cloudrequest import CloudRequest

# Cria uma sessão com bypass Cloudflare
session = CloudRequest().get_session()

# Faça requisições normalmente, como se fosse o requests
response = session.get("https://site-protegido.com")
print(response.text)
```

A sessão retornada é totalmente compatível com a API do `requests`, então você pode usar `get`, `post`, `headers`, `cookies` e tudo mais normalmente:

```python
session = CloudRequest().get_session()

# GET com parâmetros
response = session.get("https://site-protegido.com/api", params={"q": "busca"})

# POST com dados
response = session.post("https://site-protegido.com/login", data={"user": "x", "pass": "y"})

# Acessando cookies e headers da resposta
print(response.status_code)
print(response.cookies)
```

---

## 🏆 Créditos Especiais

Este projeto só existe graças ao trabalho brilhante de pessoas incríveis da comunidade open source.

---

### 🧠 js2py — Piotr Dabkowski

> **Repositório:** [github.com/PiotrDabkowski/Js2Py](https://github.com/PiotrDabkowski/Js2Py)

O **js2py** é uma das bibliotecas mais impressionantes do ecossistema Python: um interpretador JavaScript escrito inteiramente em Python puro, sem depender de nenhum runtime externo como Node.js.

É graças a esse trabalho monumental que o CloudRequest consegue resolver os desafios JavaScript da Cloudflare de forma nativa, diretamente no ambiente do Kodi.

Piotr Dabkowski merece todo o reconhecimento por uma contribuição que, silenciosamente, sustenta inúmeros projetos ao redor do mundo. 🙌

---

### 🕷️ cloudscraper — VeNoMouS

> **Repositório:** [github.com/VeNoMouS/cloudscraper](https://github.com/VeNoMouS/cloudscraper)

O **cloudscraper** é a espinha dorsal deste módulo. Construído sobre o `requests`, ele implementa toda a lógica de detecção e bypass de proteções Cloudflare — do clássico IUAM ao moderno Turnstile.

Manter o cloudscraper funcional exige um trabalho contínuo de engenharia reversa à medida que a Cloudflare evolui seus mecanismos de proteção. Esse esforço é simplesmente notável e merece muito respeito.

Sem o **VeNoMouS**, bypass de Cloudflare em Python seria um pesadelo. 🎩

---

## 📄 Licenças de Dependências

Este projeto faz uso das seguintes bibliotecas open source, cada uma sob sua respectiva licença:

| Biblioteca | Autor | Licença | Link |
|---|---|---|---|
| [js2py](https://github.com/PiotrDabkowski/Js2Py) | Piotr Dabkowski | MIT | [Ver licença](https://opensource.org/licenses/MIT) |
| [requests-toolbelt](https://github.com/requests/toolbelt) | Ian Cordasco, Cory Benfield | Apache 2.0 | [Ver licença](https://www.apache.org/licenses/LICENSE-2.0) |

---

*Feito com ❤️ pela **oneplay team***
