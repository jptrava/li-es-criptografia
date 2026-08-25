ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def cesar(texto, chave, modo="cifrar"):
    texto_upper = texto.upper()
    resultado = []
    
    # Inverte a direção do deslocamento caso seja decifração
    fator = 1 if modo == "cifrar" else -1

    for char in texto_upper: 
        if char in ALFABETO:
            pos = ALFABETO.index(char)
            novo_char = ALFABETO[(pos + (fator * chave)) % len(ALFABETO)]
            resultado.append(novo_char)
        else:
            resultado.append(char)
            
    return "".join(resultado)


def decifrar(texto, chave):
    return cesar(texto, chave, modo="decifrar")


def candidatas(texto_cifrado):
    palavras_alvo = {"DE", "A", "QUE", "AO"}
    opcoes = []

    for chave_tentativa in range(len(ALFABETO)):
        tentativa = decifrar(texto_cifrado, chave_tentativa)
        termos = tentativa.split()
        pontos = sum(termos.count(alvo) for alvo in palavras_alvo)

        opcoes.append({
            'pontuacao': pontos,
            'chave': chave_tentativa,
            'texto': tentativa
        })

        print(f"Chave: {chave_tentativa:2d} | Pontos: {pontos} | Tentativa: '{tentativa}'")

    return sorted(opcoes, key=lambda item: item['pontuacao'], reverse=True)


mensagem_original = "AO QUE TUDO INDICA"
chave_secreta = 3

print("=== ETAPA 1: CIFRAÇÃO ===")
print(f"Texto original: '{mensagem_original}'")
print(f"Aplicando algoritmo de César com chave {chave_secreta}")
texto_cifrado = cesar(mensagem_original, chave_secreta)
print(f"Resultado: '{texto_cifrado}'\n")

print("=== ETAPA 2: DECIFRAÇÃO LEGÍTIMA ===")
print(f"Texto cifrado recebido: '{texto_cifrado}'")
print(f"Revertendo com a chave correta conhecida ({chave_secreta})")
texto_recuperado = decifrar(texto_cifrado, chave_secreta)
print(f"Resultado: '{texto_recuperado}'\n")

print("=== ETAPA 3: ATAQUE DE BUSCA EXAUSTIVA ===")
print(f"Texto cifrado: '{texto_cifrado}'")
melhores = candidatas(texto_cifrado)

print("\n=== RESULTADO FINAL DO ATAQUE ===")
print("O algoritmo estatístico ordenou as opções e sugere:")
print(f" -> Chave Provável: {melhores[0]['chave']}")
print(f" -> Texto Recuperado: '{melhores[0]['texto']}'")
print(f" -> Pontuação de Confiança: {melhores[0]['pontuacao']}")
