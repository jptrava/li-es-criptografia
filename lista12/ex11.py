import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P, Q, G = 23, 11, 2


def validar(y):
    # type(y) is int deixa True e 2.0 de fora (bool é subclasse de int)
    if type(y) is not int:
        return False
    # faixa 2..p-2 e pertencimento ao subgrupo de ordem 11
    return 2 <= y <= P - 2 and pow(y, Q, P) == 1


def checar_privada(x):
    if type(x) is not int or not 1 <= x <= Q - 1:
        raise ValueError(f"privada inválida: {x!r}")


def acordo_auditado(a, b):
    checar_privada(a)
    checar_privada(b)
    A, B = pow(G, a, P), pow(G, b, P)
    if not (validar(A) and validar(B)):
        raise ValueError("pública fora do subgrupo")
    return A, B, pow(B, a, P), pow(A, b, P)


def mallory(a, b, u, v):
    """Alice recebe U e Bob recebe V, ambos escolhidos por Mallory."""
    A, B = pow(G, a, P), pow(G, b, P)
    U, V = pow(G, u, P), pow(G, v, P)
    return {
        "U": U, "V": V,
        "alice": pow(U, a, P), "mallory_alice": pow(A, u, P),
        "bob": pow(V, b, P), "mallory_bob": pow(B, v, P),
    }


def derivar(segredo, sal, info):
    # objeto novo a cada derivação
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sal, info=info).derive(segredo)


if __name__ == "__main__":
    print("acordo (2, 5):", acordo_auditado(2, 5))
    print("Mallory (2, 5, 1, 2):", mallory(2, 5, 1, 2))
    for y in (-1, 0, 1, 4, 5, 22, 23, True, 2.0):
        print("validar", repr(y), "->", validar(y))

    # parte X25519: contexto, rejeição de pública nula e replay
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    seg = a.exchange(b.public_key())
    sal, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    chave = derivar(seg, sal, b"alice->bob")
    pacote = AESGCM(chave).encrypt(nonce, b"nota=8.5", b"v1")
    print("abre com o mesmo contexto:", AESGCM(derivar(seg, sal, b"alice->bob")).decrypt(nonce, pacote, b"v1"))
    try:
        AESGCM(derivar(seg, sal, b"bob->alice")).decrypt(nonce, pacote, b"v1")
    except InvalidTag:
        print("contexto diferente: InvalidTag")
    try:
        a.exchange(X25519PublicKey.from_public_bytes(bytes(32)))
    except ValueError:
        print("pública de zeros: ValueError")
    # o mesmo pacote válido abre de novo: a etiqueta não barra replay
    print("replay aceito:", AESGCM(chave).decrypt(nonce, pacote, b"v1") == b"nota=8.5")
