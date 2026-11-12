from math import gcd

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def preparar(p, q, e):
    # p e q já chegam primos e distintos
    phi = (p - 1) * (q - 1)
    # e precisa ser coprimo com phi, senão não existe inverso
    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError(f"e = {e} não é coprimo com {phi}")
    return p * q, pow(e, -1, phi)


def transformar(m, expoente, n):
    # não reduz -1 nem n em silêncio, só aceita 0..n-1
    if not 0 <= m < n:
        raise ValueError(f"{m} fora do intervalo 0..{n - 1}")
    return pow(m, expoente, n)


def oaep(label=None):
    h = hashes.SHA256()
    return padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=label)


def pss():
    # sal de 32 bytes, igual ao tamanho do SHA-256
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def nova_chave():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


if __name__ == "__main__":
    # parte 1: RSA bruto com números pequenos
    n, d = preparar(7, 13, 5)
    m, r = 9, 2
    c = transformar(m, 5, n)
    c2 = c * r**5 % n  # multiplica a cifra por r^e, sem usar d
    print(f"n = {n}, d = {d}")
    print(f"cifra: previsto 81, obtido {c}")
    print(f"cifra x r^e: previsto 44, obtido {c2}")
    print(f"decifrada: previsto 18, obtido {transformar(c2, d, n)}")

    # parte 2: OAEP com a biblioteca
    chave = nova_chave()
    pub = chave.public_key()
    o1 = pub.encrypt(b"pedido=7", oaep())
    o2 = pub.encrypt(b"pedido=7", oaep())
    print("OAEP: cifras diferentes:", o1 != o2)
    print("OAEP: as duas abrem:", chave.decrypt(o1, oaep()) == chave.decrypt(o2, oaep()) == b"pedido=7")

    # parte 3: PSS. verify não devolve True, só levanta exceção se falhar
    sig = chave.sign(b"pedido=7", pss(), hashes.SHA256())
    pub.verify(sig, b"pedido=7", pss(), hashes.SHA256())
    print("PSS: original verificado sem exceção")
    try:
        pub.verify(sig, b"pedido=8", pss(), hashes.SHA256())
    except InvalidSignature:
        print("PSS: mensagem alterada rejeitada")
