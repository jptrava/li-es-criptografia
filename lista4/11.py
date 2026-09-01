from functools import reduce

def xor_bytes(*valores):
  
    return bytes(reduce(lambda a, b: a ^ b, byte_grupo) for byte_grupo in zip(*valores))

m1 = b"pagar=1000"
m2 = b"pagar=9000"
fluxo_reutilizado = bytes.fromhex("00112233445566778899")

c1 = xor_bytes(m1, fluxo_reutilizado)
c2 = xor_bytes(m2, fluxo_reutilizado)


recuperada = xor_bytes(c1, c2, m1)

assert recuperada == m2

print("m1:", m1)
print("m2:", m2)
print("c1 (hex):", c1.hex())
print("c2 (hex):", c2.hex())
print("c1 xor c2:", xor_bytes(c1, c2).hex())
print("m1 xor m2:", xor_bytes(m1, m2).hex())
print("recuperada:", recuperada)
print("recuperada == m2 ?", recuperada == m2)

print()
print("--- trocando o fluxo por outro do mesmo tamanho ---")
outro_fluxo = bytes.fromhex("aabbccddeeff00112233")
c1_b = xor_bytes(m1, outro_fluxo)
c2_b = xor_bytes(m2, outro_fluxo)
print("identidade continua valendo?", xor_bytes(c1_b, c2_b) == xor_bytes(m1, m2))

print()
print("--- usando fluxos independentes para cada mensagem ---")
fluxo_a = bytes.fromhex("00112233445566778899")
fluxo_b = bytes.fromhex("998877665544332211ff")
c1_indep = xor_bytes(m1, fluxo_a)
c2_indep = xor_bytes(m2, fluxo_b)
print("identidade continua valendo?", xor_bytes(c1_indep, c2_indep) == xor_bytes(m1, m2))


#PARAGRAFO

# O teste confirma na prática o que a álgebra já mostrava: quando duas mensagens são
# cifradas com o mesmo fluxo de chave, C1 ⊕ C2 é sempre igual a M1 ⊕ M2, porque a chave
# se cancela na operação (S ⊕ S = 0). Isso foi verificado tanto com o fluxo original
# quanto com outro fluxo de mesmo tamanho -- a identidade se mantém em qualquer um dos
# dois casos, já que o cancelamento depende só de as duas mensagens terem sido cifradas
# com o mesmo S, não do valor específico dele. Foi justamente essa identidade que
# permitiu recuperar m2 sabendo apenas c1, c2 e m1, sem nunca conhecer a chave usada.
# Quando cada mensagem é cifrada com um fluxo independente, porém, o cancelamento não
# ocorre mais (o teste retornou False), o que mostra que o problema não é o XOR em si,
# e sim a reutilização da chave -- exatamente a condição de uso único exigida pelo
# one-time pad para garantir sigilo perfeito.
