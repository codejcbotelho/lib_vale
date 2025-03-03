#lib_vale

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
1. Secret para credenciais do banco de dados (com campos `username` e `password`)
2. Secret `secret-token-jwt` contendo o campo `salt` para assinatura JWT

### DynamoDB

Requer uma tabela chamada `vale-tokens` para armazenamento dos tokens JWT.

## Segurança

- Senhas são armazenadas com hash SHA-256
- Tokens JWT com expiração de 30 dias
- Validação de formato de email
- Timeout configurado para conexões de banco de dados
- Logging detalhado para auditoria

## Desenvolvimento e Testes

Para testar localmente, use o script `invoke_test.py`:

