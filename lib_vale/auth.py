import pymysql
import json
import logging
import boto3
import jwt
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from lib_vale.enums import UserStatus, TokenExpiration

# Configuração do logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Login:
    def __init__(self, host: str, dbname: str, table: str, secret_name: str, region_name: str = "us-east-1"):
        """
        Inicializa a biblioteca de autenticação.

        :param host: Endereço do servidor MySQL.
        :param dbname: Nome do banco de dados
        :param table: Nome da tabela de usuários
        :param secret_name: Nome do secret no AWS Secrets Manager
        :param region_name: Região AWS do Secrets Manager
        """
        self.host = host
        self.table = table
        self.dbname = dbname
        
        # Buscar credenciais do Secrets Manager
        try:
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=region_name
            )
            
            # Buscar credenciais do banco
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
            
            if 'SecretString' in get_secret_value_response:
                secret = json.loads(get_secret_value_response['SecretString'])
                self.db_user = secret.get('username')
                self.db_password = secret.get('password')
                logger.info(f"Credenciais recuperadas com sucesso do Secrets Manager")

            # Buscar salt do JWT
            jwt_secret_response = client.get_secret_value(
                SecretId='secret-token-jwt'
            )
            
            if 'SecretString' in jwt_secret_response:
                jwt_secret = json.loads(jwt_secret_response['SecretString'])
                self.jwt_secret = jwt_secret.get('salt')
                logger.info("Salt do JWT recuperado com sucesso do Secrets Manager")
            
        except ClientError as e:
            logger.error(f"Erro ao buscar secrets do Secrets Manager: {str(e)}")
            raise Exception("Falha ao recuperar credenciais necessárias")

        logger.info(f"ValeAuth inicializado para host: {host}, database: {dbname}, tabela: {table}")

        # Inicializar cliente DynamoDB
        self.dynamodb = boto3.resource('dynamodb', region_name=region_name)
        self.tokens_table = self.dynamodb.Table('vale-tokens')

    def authenticate(self, user: str, psw: str, service_name: str = "trocai"):
        """
        Autentica um usuário e gera um token JWT.

        :param user: Email do usuário.
        :param psw: Senha do usuário.
        :param service_name: Nome do serviço que está chamando a autenticação.
        :return: Tupla (user_id, status, token) ou (None, USUARIO_NAO_ENCONTRADO, None) caso falhe.
        """
        if not self._validate_email(user):
            logger.warning(f"Tentativa de autenticação com email inválido: {user}")
            return None, UserStatus.USUARIO_NAO_ENCONTRADO.value, None

        try:
            logger.info(f"Tentando autenticar usuário: {user}")
            # Conectar ao banco de dados MySQL
            connection = pymysql.connect(
                host=self.host,
                user=self.db_user,
                password=self.db_password,
                database=self.dbname,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5  # Define um timeout para evitar longas esperas
            )
            
            with connection.cursor() as cursor:
                # Consulta SQL para buscar usuário com senha criptografada (SHA2 256)
                query = f"""
                SELECT id, status_user FROM {self.table} 
                WHERE user = %s AND psw = SHA2(%s, 256)
                """
                logger.debug(f"Executando query para usuário: {user}")
                cursor.execute(query, (user, psw))
                result = cursor.fetchone()

            connection.close()

            if result:
                logger.info(f"Usuário {user} autenticado com sucesso. ID: {result['id']}")
                
                # Gerar token JWT
                expiration = datetime.utcnow() + TokenExpiration.SEVEN_DAYS.value
                expiration_epoch = int(expiration.timestamp())
                
                token_payload = {
                    "user_id": result["id"],
                    "email": user,
                    "exp": expiration
                }
                
                token = jwt.encode(
                    token_payload,
                    self.jwt_secret,
                    algorithm="HS256"
                )
                
                # Armazenar token no DynamoDB com TTL
                try:
                    self.tokens_table.put_item(
                        Item={
                            'service': service_name,
                            'jwt': token,
                            'user_id': result["id"],
                            'email': user,
                            'expiration': expiration.isoformat(),
                            'created_at': datetime.utcnow().isoformat(),
                            'expires_at': expiration_epoch  # Campo TTL para auto-remoção
                        }
                    )
                    logger.info(f"Token JWT armazenado com sucesso para usuário {user}")
                except Exception as e:
                    logger.error(f"Erro ao armazenar token no DynamoDB: {str(e)}")
                
                return result["id"], result["status_user"], token
            else:
                logger.warning(f"Falha na autenticação para usuário: {user}")
                return None, UserStatus.USUARIO_NAO_ENCONTRADO.value, None

        except pymysql.MySQLError as e:
            logger.error(f"Erro de banco de dados durante autenticação: {str(e)}")
            return None, UserStatus.USUARIO_NAO_ENCONTRADO.value, None

    @staticmethod
    def _validate_email(email: str) -> bool:
        """
        Valida se o email informado está no formato correto.

        :param email: String do email.
        :return: True se for válido, False caso contrário.
        """
        import re
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email))

    def verify_and_renew_token(self, token: str, service_name: str) -> tuple:
        """
        Verifica se um token JWT é válido e o renova por mais 30 segundos se necessário.

        :param token: Token JWT a ser verificado
        :param service_name: Nome do serviço (ex: trocai)
        :return: Tupla (bool, str, dict) contendo (is_valid, message, token_data)
            is_valid: True se o token for válido ou renovado com sucesso
            message: Mensagem descritiva do resultado
            token_data: Dicionário com dados do token (None se inválido)
        """
        try:
            # Verificar se o token existe no DynamoDB
            response = self.tokens_table.get_item(
                Key={
                    'service': service_name,
                    'jwt': token
                }
            )

            logger.info(f"Token encontrado para o serviço {service_name}: {response}")
            
            if 'Item' not in response:
                logger.warning(f"Token não encontrado para o serviço {service_name}")
                return False, "Token não encontrado", None
            
            token_item = response['Item']
            expiration = datetime.fromisoformat(token_item['expiration'])
            
            # Verificar se o token está expirado
            if expiration < datetime.utcnow():
                logger.warning(f"Token expirado para usuário {token_item['email']}")
                return False, "Token expirado", None
            
            # Token válido, renovar por 30 segundos
            new_expiration = datetime.utcnow() + TokenExpiration.SEVEN_DAYS.value
            expiration_epoch = int(new_expiration.timestamp())
            
            # Atualizar apenas a expiração no DynamoDB, mantendo o mesmo token
            self.tokens_table.update_item(
                Key={
                    'service': service_name,
                    'jwt': token
                },
                UpdateExpression='SET expiration = :exp, expires_at = :ttl',
                ExpressionAttributeValues={
                    ':exp': new_expiration.isoformat(),
                    ':ttl': expiration_epoch
                }
            )
            
            logger.info(f"Token renovado com sucesso para usuário {token_item['email']}")
            return True, "Token renovado com sucesso", {
                'token': token,  # Retorna o mesmo token
                'user_id': int(token_item["user_id"]),
                'email': token_item["email"],
                'expiration': new_expiration.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erro ao verificar/renovar token: {str(e)}")
            return False, f"Erro ao processar token: {str(e)}", None