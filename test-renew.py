from lib_vale.auth import Auth

# Instanciar a classe Auth
auth = Auth(
    secret_name="secret-trocai-db"
)

is_valid, message, token_data = auth.verify_and_renew_token(
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMiwiZW1haWwiOiJqb2FvY2xhdWRpb2JyOTJAZ21haWwuY29tIiwiZXhwIjoxNzQxNjYxMDMzfQ.WdxS5KiBOhj6tsNTm4q1DyytHcnv_6UGHeBra7q5hFA"
)

if is_valid:
    print(f"Token renovado: {token_data['token']}")
else:
    print(f"Erro: {message}")