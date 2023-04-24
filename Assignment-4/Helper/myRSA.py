import base64
import random
import math

random.seed(42)


def StringToIntegerBlocks(msg, blockSize):
    blocksOfIntegers = []
    listOfSubstrings = [msg[i:i + blockSize] for i in range(0, len(msg), blockSize)]

    for subString in listOfSubstrings:
        if len(subString) < blockSize:
            subString += '§' * (blockSize - len(subString))

        integerBlock = 0
        for c in subString:
            integerBlock = (integerBlock << 8) | ord(c)

        blocksOfIntegers.append(integerBlock)

    return blocksOfIntegers


def IntegerBlocksToString(blocksOfIntegers, blockSize):
    text = ""
    for integerBlock in blocksOfIntegers:
        for _ in range(blockSize):
            _chr = chr((integerBlock & (255 << (8 * (blockSize - 1)))) >> (8 * (blockSize - 1)))
            if _chr != '§':
                text += _chr
            integerBlock = integerBlock << 8

    return text


def ExtendedGCD(a, b):
    if a == 0:
        return b, 0, 1

    g, y, x = ExtendedGCD(b % a, a)
    return g, x - (b // a) * y, y


def ModularInverse(a, m):
    g, x, y = ExtendedGCD(a, m)
    if g != 1:
        raise Exception("Eh")
    else:
        return x % m


def GenerateKeyPair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Find e such that e & phi are co-prime
    while True:
        e = random.randrange(3, phi)
        g, _, _ = ExtendedGCD(e, phi)

        if g == 1:
            break

    d = ModularInverse(e, phi)

    return (d, n), (e, n)


def Encrypt(msg, encryptKey):
    k, n = encryptKey
    blockSize = int(math.log(n, 2) // 8)

    ciphertextBlocks = [pow(p, k, n) for p in StringToIntegerBlocks(msg, blockSize)]
    ciphertext = IntegerBlocksToString(ciphertextBlocks, blockSize + 1)
    ciphertext = base64.b64encode(ciphertext.encode()).decode()

    return ciphertext


def Decrypt(ciphertext, decryptKey):
    k, n = decryptKey
    blockSize = int(math.log(n, 2) // 8)

    ciphertext = base64.b64decode(ciphertext).decode()
    plaintextBlocks = [pow(p, k, n) for p in StringToIntegerBlocks(ciphertext, blockSize + 1)]
    plaintext = IntegerBlocksToString(plaintextBlocks, blockSize)

    return plaintext


def Test():
    pv = (233, 713)
    pu = (17, 713)
    hs = ['Hi1', '6bb57451591395560560cb96e6047708e397a62c8a4448d2d34da5ed0b498b46|641a6b54244c2370cc5f08eb1a2a6ab5c67703d5fb54d58822eb9fc791ef90c8']

    for h in hs:
        e = Encrypt(h, pu)
        d = Decrypt(e, pv)
        print(h, " <> ", d)
        assert h == d


if __name__ == "__main__":
    K11, K12 = GenerateKeyPair(139, 151)
    print(K11, K12)
    K21, K22 = GenerateKeyPair(83, 89)
    print(K21, K22)
    K31, K32 = GenerateKeyPair(101, 127)
    print(K31, K32)
    K41, K42 = GenerateKeyPair(107, 113)
    print(K41, K42)
    K51, K52 = GenerateKeyPair(131, 109)
    print(K51, K52)
