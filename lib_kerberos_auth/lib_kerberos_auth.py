import pymysql
import json
import os
import logging
import boto3
from botocore.exceptions import ClientError
from lib_kerberos_enum import UserStatus

# Configuração do logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class KerberosAuth:
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
            
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
            
            if 'SecretString' in get_secret_value_response:
                secret = json.loads(get_secret_value_response['SecretString'])
                self.db_user = secret.get('username')
                self.db_password = secret.get('password')
                logger.info(f"Credenciais recuperadas com sucesso do Secrets Manager")
            
        except ClientError as e:
            logger.error(f"Erro ao buscar credenciais do Secrets Manager: {str(e)}")
            raise Exception("Falha ao recuperar credenciais do banco de dados")

        logger.info(f"KerberosAuth inicializado para host: {host}, database: {dbname}, tabela: {table}")

    def authenticate(self, user: str, psw: str):
        """
        Autentica um usuário verificando suas credenciais no banco de dados.

        :param user: Email do usuário.
        :param psw: Senha do usuário.
        :return: Tupla (user_id, user_status) ou (None, USUARIO_NAO_ENCONTRADO) caso falhe.
        """
        if not self._validate_email(user):
            logger.warning(f"Tentativa de autenticação com email inválido: {user}")
            return None, UserStatus.USUARIO_NAO_ENCONTRADO.value

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
                return result["id"], result["status_user"]
            else:
                logger.warning(f"Falha na autenticação para usuário: {user}")
                return None, UserStatus.USUARIO_NAO_ENCONTRADO.value

        except pymysql.MySQLError as e:
            logger.error(f"Erro de banco de dados durante autenticação: {str(e)}")
            return None, UserStatus.USUARIO_NAO_ENCONTRADO.value

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
