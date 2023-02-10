import hashlib


mapping = {
    'a': 'aa',
    'b': 'ab',
    'c': 'ac',
    'd': 'ad',
    'e': 'ae',
    'f': 'af',
    'g': 'ag',
    'h': 'ah',
    'i': 'ai',
    'j': 'aj',
    'k': 'ak',
    'l': 'al',
    'm': 'am',
    'n': 'an',
    'o': 'ao',
    'p': 'ap',
    'q': 'aq',
    'r': 'ar',
    's': 'as',
    't': 'at',
    'u': 'au',
    'v': 'av',
    'w': 'aw',
    'x': 'ax',
    'y': 'ay',
    'z': 'az',
    'A': 'ba',
    'B': 'bb',
    'C': 'bc',
    'D': 'bd',
    'E': 'be',
    'F': 'bf',
    'G': 'bg',
    'H': 'bh',
    'I': 'bi',
    'J': 'bj',
    'K': 'bk',
    'L': 'bl',
    'M': 'bm',
    'N': 'bn',
    'O': 'bo',
    'P': 'bp',
    'Q': 'bq',
    'R': 'br',
    'S': 'bs',
    'T': 'bt',
    'U': 'bu',
    'V': 'bv',
    'W': 'bw',
    'X': 'bx',
    'Y': 'by',
    'Z': 'bz',
    '0': 'ca',
    '1': 'cb',
    '2': 'cc',
    '3': 'cd',
    '4': 'ce',
    '5': 'cf',
    '6': 'cg',
    '7': 'ch',
    '8': 'ci',
    '9': 'cj',
}


def property_pi(text):
    hashDigest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    modifiedHashDigest = ''

    for x in hashDigest:
        modifiedHashDigest += mapping[x]

    return modifiedHashDigest


def apply_property_pi(text):
    propertyPiText = property_pi(text)
    plaintext = text + propertyPiText

    return plaintext


def verify_property_pi(text):
    plaintext = text[:-128]
    givenPiText = text[-128:]
    calculatedPiText = property_pi(plaintext)

    if givenPiText == calculatedPiText:
        return True
    else:
        return False


def poly_alphabetic_encrypt(plaintext, key):
    modifiedPlaintext = apply_property_pi(plaintext)
    print('Plaintext [Original Text + Pi(Original Text)]: {}'.format(modifiedPlaintext))
    keyLength = len(key)
    ciphertext = ''

    for i in range(len(modifiedPlaintext)):
        p_i = ord(modifiedPlaintext[i])
        k_i = ord(key[i % keyLength]) - 97
        c_i = chr((p_i - 97 + k_i) % 26 + 97)
        ciphertext += c_i

    return ciphertext


def poly_alphabetic_decrypt(ciphertext, key):
    keyLength = len(key)
    decryptedPlainText = ''

    for i in range(len(ciphertext)):
        c_i = ord(ciphertext[i])
        k_i = ord(key[i % keyLength]) - 97
        p_i = chr((c_i - 97 - k_i) % 26 + 97)
        decryptedPlainText += p_i

    if not verify_property_pi(decryptedPlainText):
        return None

    print('Decrypted Plain Text: {}'.format(decryptedPlainText))
    decryptedOriginalText = decryptedPlainText[:-128]

    return decryptedOriginalText


if __name__ == "__main__":
    PlainText = "wearediscoveredsaveyourselfover"
    Key = "abcd"

    print('Original Text: {}'.format(PlainText))
    print('Key: {}'.format(Key))

    CipherText = poly_alphabetic_encrypt(PlainText, Key)
    print('Cipher Text: {}'.format(CipherText))

    DecryptedOriginalText = poly_alphabetic_decrypt(CipherText, Key)
    print('Decrypted Original Text: {}'.format(DecryptedOriginalText))
