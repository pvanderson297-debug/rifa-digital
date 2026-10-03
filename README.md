# Rifa Digital

Aplicação com página pública e painel do organizador. Os dados ficam no SQLite do servidor, não no navegador.

## O que falta para o link público

Esta pasta ainda não está publicada. A Vercel não foi conectada, e o plano serverless não guarda banco nem comprovantes. Falta uma hospedagem HTTPS com disco persistente, por exemplo Render, Fly.io, Railway ou um VPS, com estas variáveis:

- `RIFA_ADMIN_PASSWORD`: senha inicial do painel
- `RIFA_SECRET`: chave aleatória longa para a sessão
- `DATA_DIR`: pasta persistente, no Docker é `/data`

## Correr localmente

```bash
pip install -r requirements.txt
RIFA_ADMIN_PASSWORD=uma-senha-longa RIFA_SECRET=outra-chave-longa uvicorn app:app --host 0.0.0.0 --port 8000
```

Abra `http://localhost:8000`. O painel fica no botão Organizador e só responde depois do login no servidor.
