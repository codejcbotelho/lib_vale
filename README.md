# lib_vale

Biblioteca de autenticação para serviços Vale.

## Uso Básico

```python
from lib_vale.auth import Auth

# Inicializar a biblioteca
auth = Auth(
    secret_name="secret-trocai-db",  # Nome do secret no AWS Secrets Manager
    service_name="trocai"            # Nome do serviço (opcional, default: "trocai")
)

# Autenticar usuário
user_id, status, token = auth.authenticate(user="email@exemplo.com", psw="senha123")

# Verificar e renovar token
is_valid, message, token_data = auth.verify_and_renew_token(token="seu_token_jwt")
```

## Status de Usuário

A biblioteca implementa os seguintes status de usuário através do enum `UserStatus`:

- USUARIO_ATIVO (1)
- USUARIO_DESABILITADO (2)
- USUARIO_DESABILITADO_POR_INATIVIDADE (3)
- USUARIO_BLOQUEADO_POR_TENTATIVA_SENHA_INCORRETA (4)
- USUARIO_BLOQUEADO_POR_ATIVIDADES_SUSPEITAS (5)
- USUARIO_BLOQUEADO_POR_DESCUMPRIMENTO_REGRAS (6)
- USUARIO_PENDENTE_CONFIRMACAO_EMAIL (7)
- USUARIO_NAO_ENCONTRADO (100)

## Tempos de Expiração

A biblioteca define os seguintes tempos de expiração através do enum `TokenExpiration`:

- THIRTY_DAYS = timedelta(days=30)
- SEVEN_DAYS = timedelta(days=7)
- ONE_DAY = timedelta(days=1)
- ONE_HOUR = timedelta(hours=1)
- THIRTY_SECONDS = timedelta(seconds=30)

## Requisitos

- Python 3.6+
- PyMySQL
- boto3
- PyJWT
- Acesso ao AWS Secrets Manager
- Banco de dados MySQL
- Tabela DynamoDB para tokens

## Configuração AWS

### Secrets Manager

A biblioteca requer dois secrets no AWS Secrets Manager:

1. Secret para credenciais do banco de dados com os campos:
   - username
   - password
   - host
   - dbname
   - table

2. Secret `secret-token-jwt` contendo o campo `salt` para assinatura JWT

### DynamoDB

Requer uma tabela chamada `vale-tokens` com:
- Chave primária composta: service (partition key) e jwt (sort key)
- Campo TTL configurado como `expires_at`

## Segurança

- Senhas são armazenadas com hash SHA-256
- Tokens JWT com tempo de expiração configurável
- Auto-remoção de tokens expirados via DynamoDB TTL
- Validação de formato de email
- Timeout configurado para conexões de banco de dados
- Logging detalhado para auditoria

## Desenvolvimento e Testes

Para testar localmente, use os scripts:

### Teste de Autenticação
```python
python invoke_test.py
```

### Teste de Renovação de Token
```python
python test-renew.py
```

## Logs

A biblioteca utiliza o módulo `logging` do Python para registrar operações importantes:
- Inicialização da biblioteca
- Tentativas de autenticação
- Operações com tokens
- Erros e exceções
```
