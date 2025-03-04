import json
import os
from lib_vale.auth import Auth
from lib_vale.enums import UserStatus

def lambda_handler(event, context):
    try:
        # Configurações do banco de dados via variáveis de ambiente
        db_config = {
            "host": os.environ.get('DB_HOST'),
            "dbname": os.environ.get('DB_NAME'),
            "secret_name": os.environ.get('SECRET_NAME'),
            "table": os.environ.get('DB_TABLE')
        }
        
        # Extrair credenciais do payload
        user = event.get('user')
        password = event.get('password')
        
        if not user or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'message': 'Usuário e senha são obrigatórios',
                    'status': UserStatus.USUARIO_NAO_ENCONTRADO.value
                })
            }
        
        # Inicializar Auth
        auth = Auth(
            secret_name="secret-trocai-db"
        )
        
        # Tentar autenticar
        user_id, status, jwt = auth.authenticate(user, password)
        
        if user_id:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'user_id': user_id,
                    'status': status,
                    'token': jwt,
                    'message': 'Autenticação bem-sucedida'
                })
            }
        else:
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'message': 'Falha na autenticação',
                    'status': status
                })
            }
            
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Erro interno: {str(e)}',
                'status': UserStatus.USUARIO_NAO_ENCONTRADO.value
            })
        }