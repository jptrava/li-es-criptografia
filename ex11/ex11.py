import hashlib
import hmac
import secrets


def sha256(msg):
    return hashlib.sha256(msg).digest()


def criar_hmac(chave, msg):
    return hmac.new(chave, msg, hashlib.sha256).digest()


def verificar_hmac(chave, msg, tag):
    return hmac.compare_digest(criar_hmac(chave, msg), tag)


# --- Dados ---
orig = b"remetente=carlos;destino=beatriz;valor=250.00"
alt = b"remetente=carlos;destino=beatriz;valor=9500.00"

print("--- [1] SHA-256 (Sem Chave) ---")
h_orig = sha256(orig)
h_alt = sha256(alt)

# O servidor valida o hash recalculado pelo atacante
assert h_alt == sha256(alt)
print(f"Original : {orig.decode()} | Hash: {h_orig.hex()[:12]}...")
print(f"Alterada : {alt.decode()} | Hash: {h_alt.hex()[:12]}...")
print("FALHA: SHA-256 aceitou a mensagem alterada (qualquer um recalcula hash).\n")

print("--- [2] HMAC-SHA-256 (Com Chave) ---")
k_leg = secrets.token_bytes(32)
k_atq = secrets.token_bytes(32)

tag_orig = criar_hmac(k_leg, orig)
assert verificar_hmac(k_leg, orig, tag_orig)
print(f"Legitimo : {orig.decode()} -> APROVADO")

tag_atq = criar_hmac(k_atq, alt)
valido = verificar_hmac(k_leg, alt, tag_atq)
assert not valido
print(f"Atacante : {alt.decode()} -> REJEITADO (Validacao: {valido})")
