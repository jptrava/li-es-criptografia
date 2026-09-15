
SEGUNDOS_ANO = 365.25 * 24 * 60 * 60

def tempo_medio(bits_seguranca, testes_por_segundo, maquinas=1):
    # usa metade do espaco de chaves (tempo medio de busca exaustiva)
    return (2 ** (bits_seguranca - 1)) / (testes_por_segundo * maquinas)

def em_anos(segundos):
    return segundos / SEGUNDOS_ANO

def em_horas(segundos):
    return segundos / 3600

CENARIOS = [
    ("DES", 56),
    ("3DES (forca estimada)", 112),
    ("AES-128", 128),
]

# Este teste falha enquanto tempo_medio devolver None.
assert tempo_medio(56, 1e12) == 2 ** 55 / 1e12

# +1 bit deve dobrar o tempo
assert abs(tempo_medio(57, 1e12) / tempo_medio(56, 1e12) - 2) < 1e-9

# dobrar maquinas divide o tempo por dois
assert abs(tempo_medio(56, 1e12, 1) / tempo_medio(56, 1e12, 2) - 2) < 1e-9

# razao entre 128 e 56 bits deve ser 2**72
assert abs(tempo_medio(128, 1e12) / tempo_medio(56, 1e12) - 2**72) < 1

for nome, bits in CENARIOS:
    segundos = tempo_medio(bits, 1e12)
    print(nome, bits, em_anos(segundos))
