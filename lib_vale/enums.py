from enum import Enum
from datetime import timedelta

class UserStatus(Enum):
    """
    Enum contendo os diferentes status que um usuário pode ter no sistema.
    """
    USUARIO_ATIVO = 1  # Usuário ativo
    USUARIO_DESABILITADO = 2  # Usuário desabilitado pelo próprio usuário
    USUARIO_DESABILITADO_POR_INATIVIDADE = 3  # Desabilitado por tempo de inatividade
    USUARIO_BLOQUEADO_POR_TENTATIVA_SENHA_INCORRETA = 4  # Bloqueado por tentativas de senha incorretas
    USUARIO_BLOQUEADO_POR_ATIVIDADES_SUSPEITAS = 5  # Bloqueado por atividades suspeitas
    USUARIO_BLOQUEADO_POR_DESCUMPRIMENTO_REGRAS = 6  # Bloqueado por descumprimento de regras
    USUARIO_PENDENTE_CONFIRMACAO_EMAIL = 7  # Pendente de confirmação de email
    USUARIO_NAO_ENCONTRADO = 100  # Usuário não encontrado

class TokenExpiration(Enum):
    """
    Enum contendo os tempos de expiração para tokens
    """
    THIRTY_DAYS = timedelta(days=30)
    SEVEN_DAYS = timedelta(days=7)
    ONE_DAY = timedelta(days=1)
    ONE_HOUR = timedelta(hours=1)
    THIRTY_SECONDS = timedelta(seconds=30)  # Adicionado TTL de 30 segundos
