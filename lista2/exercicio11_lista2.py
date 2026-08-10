import secrets

def euclides_estendido(a, b):
   
    x0, x1, y0, y1 = 1, 0, 0, 1
    
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
        
    return a, x0, y0 # Retorna (mdc, x, y)

def inverso_modular(a, n):
    mdc, x, y = euclides_estendido(a, n)
    
    if mdc != 1:
        raise ValueError(f"O número {a} não possui inverso módulo {n} (MDC = {mdc}).")
    
    return x % n

def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("As sequências de bytes devem ter o mesmo tamanho para a operação XOR.")
    
    # Aplica XOR byte a byte usando zip
    return bytes(x ^ y for x, y in zip(a, b))

# ==========================================
# TESTES E EVIDÊNCIAS
# ==========================================

print("--- [1] Teste do Inverso Modular ---")
inv_7 = inverso_modular(7, 26)
print(f"O inverso de 7 mod 26 é: {inv_7}")
assert inv_7 == 15

try:
    print("Tentando calcular inverso de 6 mod 26...")
    inverso_modular(6, 26)
except ValueError as e:
    print(f"-> Sucesso ao rejeitar! Erro: {e}")

print("\n--- [2] Teste da Operação XOR ---")
resultado_xor = xor_bytes(bytes.fromhex("0f"), bytes.fromhex("f0"))
print(f"XOR entre '0f' e 'f0' resulta em (hex): {resultado_xor.hex()}")
assert resultado_xor.hex() == "ff"

print("\n--- [3] Teste de Repetição de Nonces ---")
nonces_gerados = set()
colisoes = 0

for _ in range(1000):
    nonce = secrets.token_bytes(12)
    if nonce in nonces_gerados:
        colisoes += 1
    nonces_gerados.add(nonce)

print(f"Nonces totais gerados: {len(nonces_gerados)}")
print(f"Colisões encontradas: {colisoes}")