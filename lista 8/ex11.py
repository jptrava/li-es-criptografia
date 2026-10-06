def e(x, k=3):
    return (x + k) % 16


def d(y, k=3):
    return (y - k) % 16


def checa_bloco(b):
    if b < 0 or b > 15:
        raise ValueError("bloco fora de 0 a 15")


def cbc(blocos, iv):
    checa_bloco(iv)
    saida = []
    anterior = iv
    for b in blocos:
        checa_bloco(b)
        c = e(b ^ anterior)  
        saida.append(c)
        anterior = c             
    return saida


def dec_cbc(blocos, iv):
    checa_bloco(iv)
    saida = []
    anterior = iv
    for c in blocos:
        checa_bloco(c)
        m = d(c) ^ anterior      # desfaz a cifra primeiro, depois o XOR
        saida.append(m)
        anterior = c
    return saida


def ctr(blocos, nonce, inicio=0):
    if nonce < 0 or nonce > 3:
        raise ValueError("nonce fora de 0 a 3")
    if inicio < 0 or inicio > 3:
        raise ValueError("contador fora de 0 a 3")
    if inicio + len(blocos) > 4:
        raise ValueError("contador esgotado")
    saida = []
    for i, b in enumerate(blocos):
        checa_bloco(b)
        j = inicio + i
        t = (nonce << 2) | j     # nonce e contador lado a lado
        s = e(t)                 # fluxo de chave
        saida.append(b ^ s)
    return saida


# ---- testes ----
assert cbc([6, 6, 6], 5) == [6, 3, 8]
assert ctr([6, 6, 6], 2) == [13, 10, 11]

# a inversa do CBC recupera a mensagem
assert dec_cbc([6, 3, 8], 5) == [6, 6, 6]
for iv in range(16):
    for m in ([1, 2, 3], [0, 15], [7, 7, 7, 7]):
        assert dec_cbc(cbc(m, iv), iv) == m

# CTR: repetir a operação recupera
for n in range(4):
    for m in ([6, 6, 6], [1, 2], [15, 0, 9, 4]):
        assert ctr(ctr(m, n), n) == m

# d(e(x)) = x para os 16 valores
for x in range(16):
    assert d(e(x)) == x
try:
    ctr([1, 2, 3, 4, 5], 2)
    print("ERRO: aceitou 5 blocos")
except ValueError as erro:
    print("cinco blocos recusados:", erro)

# ---- tarefa 4: mudar IV e nonce ----
msg = [6, 6, 6]
for iv in (5, 9):
    c = cbc(msg, iv)
    print("CBC iv =", iv, "saida =", c, "recuperado =", dec_cbc(c, iv))
for n in (2, 3):
    c = ctr(msg, n)
    print("CTR nonce =", n, "saida =", c, "recuperado =", ctr(c, n))

# ---- tarefa 5: mudar 1 bit em CTR ----
c = ctr(msg, 2)
c[0] ^= 1                    # inverte o bit menos significativo
print("CTR alterado, recuperado =", ctr(c, 2))   # [7, 6, 6]

print("tudo certo")
