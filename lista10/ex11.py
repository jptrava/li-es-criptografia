"""Atividade 11 - conexões certas e erradas (Encontro 10).

Acordo X25519 + HKDF-SHA256 + AES-GCM, e o ataque de intermediário
com a chave pública trocada. Só dados fictícios, tudo local.

Nenhuma função aqui imprime privadas, segredos ou chaves derivadas.
"""

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MENSAGEM = b"nota=8.5"
CONTEXTO = b"encontro10-lab-v1"

# Nonce fixo só porque cada chave derivada cifra UMA mensagem neste
# laboratório. Num sistema de verdade isso seria um erro grave.
NONCE = bytes(12)


def exportar_publica(chave_privada):
    """Os 32 bytes brutos da pública (a privada nunca sai daqui)."""
    return chave_privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def importar_publica(dados):
    return X25519PublicKey.from_public_bytes(dados)


def derivar_chave(segredo, sal, contexto=CONTEXTO):
    # HKDF guarda estado, então cria-se um objeto novo a cada derivação.
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=sal, info=contexto)
    return hkdf.derive(segredo)


def cifrar(chave, mensagem, aad=b""):
    return AESGCM(chave).encrypt(NONCE, mensagem, aad)


def abrir(chave, pacote, aad=b""):
    # levanta InvalidTag se o pacote foi alterado ou a chave está errada
    return AESGCM(chave).decrypt(NONCE, pacote, aad)


def conexao_honesta(sal=None, contexto=CONTEXTO):
    """Alice e Bob trocam as públicas de verdade, sem ninguém no meio."""
    sal = sal if sal is not None else secrets.token_bytes(16)
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()

    pub_a = importar_publica(exportar_publica(a))
    pub_b = importar_publica(exportar_publica(b))

    seg_alice = a.exchange(pub_b)
    seg_bob = b.exchange(pub_a)

    chave_alice = derivar_chave(seg_alice, sal, contexto)
    chave_bob = derivar_chave(seg_bob, sal, contexto)
    return {
        "sal": sal,
        "seg_alice": seg_alice,
        "seg_bob": seg_bob,
        "chave_alice": chave_alice,
        "chave_bob": chave_bob,
    }


def mallory_so_com_alice(sal=None):
    """Alice recebe a pública de Mallory achando que é a de Bob.

    Bob não é alterado nesta variante. Mallory refaz a conta de Alice
    usando a pública (verdadeira) de Alice e a privada dela mesma.
    """
    sal = sal if sal is not None else secrets.token_bytes(16)
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    m = X25519PrivateKey.generate()

    pub_a = importar_publica(exportar_publica(a))
    pub_b = importar_publica(exportar_publica(b))
    pub_m = importar_publica(exportar_publica(m))

    chave_alice = derivar_chave(a.exchange(pub_m), sal)  # Alice crê estar com Bob
    chave_mallory = derivar_chave(m.exchange(pub_a), sal)
    chave_bob = derivar_chave(b.exchange(pub_a), sal)  # Bob fala com a Alice real
    return {
        "chave_alice": chave_alice,
        "chave_mallory": chave_mallory,
        "chave_bob": chave_bob,
    }


def mallory_nas_duas(sal=None):
    """Mallory troca a pública nos dois sentidos e fica no meio.

    Alice -> Mallory usa uma chave; Mallory -> Bob usa outra. Mallory
    decifra, lê e recifra. Em nenhum momento ela descobre a ou b.
    """
    sal = sal if sal is not None else secrets.token_bytes(16)
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    m = X25519PrivateKey.generate()

    pub_a = importar_publica(exportar_publica(a))
    pub_b = importar_publica(exportar_publica(b))
    pub_m = importar_publica(exportar_publica(m))

    # o que cada vítima calcula com a "pública do outro" (que é a de Mallory)
    k_alice = derivar_chave(a.exchange(pub_m), sal)
    k_bob = derivar_chave(b.exchange(pub_m), sal)

    # o que Mallory calcula, um segredo para cada lado
    k_m_alice = derivar_chave(m.exchange(pub_a), sal)
    k_m_bob = derivar_chave(m.exchange(pub_b), sal)

    # Alice cifra a mensagem para "Bob"
    pacote_alice = cifrar(k_alice, MENSAGEM)

    # Mallory abre com a chave do lado da Alice e recifra para o lado do Bob
    lido = abrir(k_m_alice, pacote_alice)
    pacote_para_bob = cifrar(k_m_bob, lido)

    # Bob abre sem notar nada de estranho
    recebido = abrir(k_bob, pacote_para_bob)

    return {
        "lido_por_mallory": lido,
        "recebido_por_bob": recebido,
        "pacote_alice": pacote_alice,
        "pacote_para_bob": pacote_para_bob,
        "k_alice": k_alice,
        "k_bob": k_bob,
    }


if __name__ == "__main__":
    # Demonstração sem expor nenhum segredo: só booleanos e tamanhos.
    r = conexao_honesta()
    print("segredos iguais:", r["seg_alice"] == r["seg_bob"], "| tamanho:", len(r["seg_alice"]))
    print("chaves derivadas iguais:", r["chave_alice"] == r["chave_bob"])

    pacote = cifrar(r["chave_alice"], MENSAGEM)
    print("Bob abriu corretamente:", abrir(r["chave_bob"], pacote) == MENSAGEM)

    v = mallory_so_com_alice()
    print()
    print("Mallory tem a mesma chave da Alice:", v["chave_mallory"] == v["chave_alice"])
    print("Bob tem a mesma chave da Alice:   ", v["chave_bob"] == v["chave_alice"])

    d = mallory_nas_duas()
    print()
    print("Mallory leu a mensagem:", d["lido_por_mallory"] == MENSAGEM)
    print("Bob recebeu a mensagem:", d["recebido_por_bob"] == MENSAGEM)
    print("As duas conexões usam chaves diferentes:", d["k_alice"] != d["k_bob"])
