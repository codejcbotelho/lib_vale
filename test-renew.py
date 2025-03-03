from lib_vale.auth import Login

# Instanciar a classe Login com os parâmetros necessários
auth = Login(
    host="localhost",
    dbname="trocai",
    table="user",
    secret_name="secret-trocai-db"
)

is_valid, message, token_data = auth.verify_and_renew_token(
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMiwiZW1haWwiOiJqb2FvY2xhdWRpb2JyOTJAZ21haWwuY29tIiwiZXhwIjoxNzQxNjI1NjM0fQ.whfihqvgk1_NM0-0R7y9EGi29mK6VpilQD1StDkcBRI",
    service_name="trocai"
)

if is_valid:
    print(f"Token renovado: {token_data['token']}")
else:
    print(f"Erro: {message}")