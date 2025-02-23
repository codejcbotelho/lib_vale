from enum import Enum

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
