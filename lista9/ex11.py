from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes = AESGCM(AESGCM.generate_key(bit_length=128))
nonce = (7).to_bytes(4, "big") + (9).to_bytes(8, "big")
aad = bytes([1]) + (17).to_bytes(2, "big") + (9).to_bytes(4, "big")
mensagem = b"nota=8.5"

# Tarefa 1: cifra uma vez só e abre o registro correto
pacote = aes.encrypt(nonce, mensagem, aad)   # C seguido de T
recuperada = aes.decrypt(nonce, pacote, aad)

assert len(pacote) == 24
assert recuperada == mensagem
print("tamanhos -> C+T:", len(pacote), "| AAD:", len(aad), "| nonce:", len(nonce))
print("registro completo (A|N|C|T):", len(aad) + len(nonce) + len(pacote), "bytes")


def alterar(dados, pos):
    """Devolve uma cópia com o último bit do byte 'pos' invertido."""
    copia = bytearray(dados)
    copia[pos] ^= 1
    return bytes(copia)


def deve_falhar(nome, n, p, a, chave=aes):
    """Tenta abrir e exige InvalidTag; nunca usa o texto candidato."""
    try:
        chave.decrypt(n, p, a)
    except InvalidTag:
        print(f"[ok] {nome}: InvalidTag")
    else:
        raise AssertionError(f"{nome}: era para falhar e abriu")


# Tarefa 2: cada teste altera só um campo, sempre a partir do original
deve_falhar("C alterado (1o byte)", nonce, alterar(pacote, 0), aad)
deve_falhar("T alterada (ultimo byte)", nonce, alterar(pacote, -1), aad)
deve_falhar("AAD alterado", nonce, pacote, alterar(aad, -1))
deve_falhar("nonce alterado", alterar(nonce, -1), pacote, aad)
deve_falhar("chave errada", nonce, pacote, aad,
            chave=AESGCM(AESGCM.generate_key(bit_length=128)))

# Tarefa 3: os testes só abrem cópias; decifrar não é uma nova cifração,
# então o nonce original não é reutilizado para cifrar nada.

# Tarefa 4: repetir o registro intacto passa na biblioteca
assert aes.decrypt(nonce, pacote, aad) == mensagem
print("[ok] segunda abertura do registro intacto: valida para a biblioteca")

# Tarefa 5: controle didático de repetição (só em memória)
aceitas = set()


def receber(usuario_esperado, n, p, a):
    """Autentica primeiro; depois confere contexto e repetição."""
    try:
        texto = aes.decrypt(n, p, a)
    except InvalidTag:
        return False               

    usuario = int.from_bytes(a[1:3], "big")
    sequencia = int.from_bytes(a[3:7], "big")

    if usuario != usuario_esperado:      # Tarefa 6: contexto autenticado x esperado
        return False
    if (usuario, sequencia) in aceitas:  
        return False

    aceitas.add((usuario, sequencia))
    print("   ação efetivada com:", texto.decode())
    return True


assert receber(17, nonce, pacote, aad) is True
assert receber(17, nonce, pacote, aad) is False              
assert receber(18, nonce, pacote, aad) is False              
assert receber(17, nonce, alterar(pacote, 0), aad) is False  
assert aceitas == {(17, 9)}                                
print("[ok] repetição, contexto errado e adulteração rejeitados pela aplicação")
