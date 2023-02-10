import hashlib


# Mapping to map hash digest to {a-z}
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
    """
    Calculates the hash to be concatenated with original text
    :param text: string
    :return: string of 128 characters
    """

    # Calculate hex digest of text
    hashDigest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    modifiedHashDigest = ''

    # Map the hex digest to {a-z} as defined by mapping
    for x in hashDigest:
        modifiedHashDigest += mapping[x]

    return modifiedHashDigest


def apply_property_pi(text):
    """
    Converts original text to plaintext by concatenating the hash
    :param text: string
    :return: string
    """

    # Calculate hash
    propertyPiText = property_pi(text)

    # Concatenate original text and hash to get plaintext
    plaintext = text + propertyPiText

    return plaintext


def verify_property_pi(text):
    """
    returns True if text satisfies property pi else False
    :param text: string
    :return: boolean
    """

    # Separate text and hash (last 128 characters are hash)
    plaintext = text[:-128]
    givenPiText = text[-128:]

    # Re-calculate hash on text
    calculatedPiText = property_pi(plaintext)

    # Return True/False based on equality of hash and re-calculated hash
    if givenPiText == calculatedPiText:
        return True
    else:
        return False


def poly_alphabetic_encrypt(originalText, key):
    """
    Calculates plaintext from original text, encrypts plaintext using key and returns ciphertext
    :param originalText: string
    :param key: string
    :return: string
    """

    # Calculate plaintext from original text
    modifiedPlaintext = apply_property_pi(originalText)
    print('Plaintext [Original Text + Pi(Original Text)]: {}'.format(modifiedPlaintext))

    keyLength = len(key)
    ciphertext = ''

    # Calculate ciphertext character by character
    for i in range(len(modifiedPlaintext)):
        p_i = ord(modifiedPlaintext[i])
        k_i = ord(key[i % keyLength]) - 97
        c_i = chr((p_i - 97 + k_i) % 26 + 97)
        ciphertext += c_i

    return ciphertext


def poly_alphabetic_decrypt(ciphertext, key):
    """
    Decrypts given ciphertext using key, calculates original text from decrypted plaintext returns original text
    :param ciphertext: string
    :param key: string
    :return: string
    """
    keyLength = len(key)
    decryptedPlainText = ''

    # Calculate plaintext character by character
    for i in range(len(ciphertext)):
        c_i = ord(ciphertext[i])
        k_i = ord(key[i % keyLength]) - 97
        p_i = chr((c_i - 97 - k_i) % 26 + 97)
        decryptedPlainText += p_i

    # Verification of property pi on decrypted plaintext
    if not verify_property_pi(decryptedPlainText):
        return None

    print('Decrypted Plain Text: {}'.format(decryptedPlainText))
    decryptedOriginalText = decryptedPlainText[:-128]

    return decryptedOriginalText


def encrypt_decrypt(originalText, key):
    """
    Performs all the encryption-decryption steps and prints initial, intermediate and final results
    :param originalText: string
    :param key: string
    :return: None
    """
    print("--------------------")
    print('Original Text: {}'.format(originalText))
    print('Key: {}'.format(key))

    # Encryption
    CipherText = poly_alphabetic_encrypt(originalText, key)
    print('Cipher Text: {}'.format(CipherText))

    # Decryption
    DecryptedOriginalText = poly_alphabetic_decrypt(CipherText, key)
    print('Decrypted Original Text: {}'.format(DecryptedOriginalText))
    print("--------------------")


if __name__ == "__main__":
    encrypt_decrypt("wearediscoveredsaveyourselfover", "abcd")
    encrypt_decrypt("thisisasampletext", "abcd")
    encrypt_decrypt("mynameisyash", "abcd")
    encrypt_decrypt("ilovesummer", "abcd")
    encrypt_decrypt("bruteforceattackiscostly", "abcd")
