import os
from test import lambda_handler

# Configurar variáveis de ambiente necessárias
os.environ['DB_HOST'] = 'localhost'  # ou seu host do banco
os.environ['DB_NAME'] = 'trocai'     # nome do seu banco
os.environ['DB_TABLE'] = 'user'      # nome da tabela
os.environ['SECRET_NAME'] = 'secret-trocai-db'  # nome do seu secret

# Simular o evento da Lambda com o payload
event = {
    "user": "joaoclaudiobr92@gmail.com",
    "password": "minhasenha"
}

# Simular o contexto da Lambda (pode ser None para teste local)
context = None

# Invocar a função handler
response = lambda_handler(event, context)

# Exibir resultado
print("Status Code:", response['statusCode'])
print("Response Body:", response['body']) 