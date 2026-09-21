def xtime(valor):
    # multiplica por x (byte 0x02): desloca 1 bit a esquerda e, se estourou o oitavo bit,
    # reduz fazendo XOR com 0x1B (os termos de x^8 = x^4+x^3+x+1)
    deslocado = (valor << 1) & 0xFF
    if valor & 0x80:
        deslocado ^= 0x1B
    return deslocado
 
def gf_mul(a, b):
    # multiplicacao geral: soma (XOR) as potencias de x cujo bit em b esta ligado
    resultado = 0
    for _ in range(8):
        if b & 1:
            resultado ^= a
        b >>= 1
        a = xtime(a)
    return resultado
 
assert xtime(0x57) == 0xAE
assert gf_mul(0x57, 0x13) == 0xFE
 
print("--- testes basicos do enunciado ---")
print("xtime(0x57) =", hex(xtime(0x57)))
print("gf_mul(0x57, 0x13) =", hex(gf_mul(0x57, 0x13)))
 
print()
print("--- tarefa 3: parcelas de 57 * 13 ---")
# 0x13 = 0001 0011, bits ligados nos expoentes 0, 1 e 4
potencias = [0x57]
for _ in range(4):
    potencias.append(xtime(potencias[-1]))
for i, valor in enumerate(potencias):
    print(f"x^{i} * 57 = {hex(valor)}")
bits_13 = [i for i in range(5) if (0x13 >> i) & 1]
print("bits ligados em 0x13:", bits_13)
parcelas = [potencias[i] for i in bits_13]
soma = 0
for p in parcelas:
    soma ^= p
print("parcelas somadas (XOR):", [hex(p) for p in parcelas], "=", hex(soma))
 
print()
print("--- tarefa 4: conferindo todos os bytes de 0x00 a 0xFF ---")
zero_ok = all(gf_mul(x, 0x00) == 0x00 for x in range(256))
um_ok = all(gf_mul(x, 0x01) == x for x in range(256))
dois_ok = all(gf_mul(x, 0x02) == xtime(x) for x in range(256))
print("multiplicar por 0x00 sempre da 0?", zero_ok)
print("multiplicar por 0x01 preserva o byte?", um_ok)
print("multiplicar por 0x02 bate com xtime?", dois_ok)
 
print()
print("--- tarefa 5: MixColumns em [D4, BF, 5D, 30] ---")
coluna = [0xD4, 0xBF, 0x5D, 0x30]
d, b, c, e = coluna
b0 = gf_mul(2, d) ^ gf_mul(3, b) ^ gf_mul(1, c) ^ gf_mul(1, e)
b1 = gf_mul(1, d) ^ gf_mul(2, b) ^ gf_mul(3, c) ^ gf_mul(1, e)
b2 = gf_mul(1, d) ^ gf_mul(1, b) ^ gf_mul(2, c) ^ gf_mul(3, e)
b3 = gf_mul(3, d) ^ gf_mul(1, b) ^ gf_mul(1, c) ^ gf_mul(2, e)
print(f"produtos da primeira linha: 2*D4={hex(gf_mul(2,d))}  3*BF={hex(gf_mul(3,b))}  1*5D={hex(gf_mul(1,c))}  1*30={hex(gf_mul(1,e))}")
print("XOR dos quatro produtos (b0):", hex(b0))
assert b0 == 0x04
coluna_final = [b0, b1, b2, b3]
print("coluna misturada completa:", [hex(v) for v in coluna_final])
 
print()
print("--- tarefa 6: reducao longa (9 bits) vs reducao curta (mask + 0x1B), usando AE ---")
valor = 0xAE
nove_bits = valor << 1
reducao_longa = nove_bits ^ 0x11B if (valor & 0x80) else nove_bits
reducao_curta = xtime(valor)
print("AE deslocado (9 bits):", hex(nove_bits))
print("reduzindo com XOR 0x11B direto:", hex(reducao_longa))
print("guardando so os 8 bits baixos e fazendo XOR com 0x1B:", hex(reducao_curta))
print("as duas formas batem?", reducao_longa == reducao_curta)
 
print()
print("Todos os testes passaram sem erro.")
