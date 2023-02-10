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


def is_key_valid(ciphertext, key):
    """
    Checks validity of key for given ciphertext, returns True if valid else False
    :param ciphertext: string
    :param key: string
    :return: boolean
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
    # If property pi satisfies then key is valid for given ciphertext, else not valid
    if verify_property_pi(decryptedPlainText):
        return True
    else:
        return False


def launch_brute_force_attack(listOfCipherTexts):
    """
    Launches brute force attack to discover key. It is known that key length is 4. All possible keys in lexicographic
    order are checked. For each key checks if decrypted plaintext satisfies property pi for ciphertexts one by one.
    If not, moves to next key. The key for which all the ciphertexts are successfully decrypted with recognizability
    test passing is returned as the discovered key
    :param listOfCipherTexts: list of strings
    :return: string
    """
    charSet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    numOfCipherTexts = len(listOfCipherTexts)

    # Check all possible keys in lexicographic order
    for key_char_1 in charSet:
        for key_char_2 in charSet:
            for key_char_3 in charSet:
                for key_char_4 in charSet:
                    currentKey = key_char_1 + key_char_2 + key_char_3 + key_char_4
                    print('Checking key: {}'.format(currentKey))

                    # Counter to track how many decrypted plaintexts are recognizable for current key
                    currentKeyValidForCipherTexts = 0

                    # Check key validity for each ciphertext
                    for currentCipherText in listOfCipherTexts:
                        # If current key fails for even one ciphertext, skip to next key
                        if not is_key_valid(currentCipherText, currentKey):
                            continue
                        else:
                            # Update counter for each ciphertext the current key is valid for
                            currentKeyValidForCipherTexts += 1
                            print('Key: {} is valid for ciphertext: {}'.format(currentKey, currentCipherText))

                    # If current key is valid for all ciphertexts, then current key is the discovered key
                    if currentKeyValidForCipherTexts == numOfCipherTexts:
                        print('Key: {} is valid for all ciphertexts'.format(currentKey))
                        return currentKey


if __name__ == "__main__":
    # Key: aayb
    # ListOfCipherTexts = [
    #     'weysedgtcotfrebtavczoupteldpvepdfaydbaadgacdaccbecbdhaadjcedeczddcaddacdbcgdiacbbcedcabbaczbbacdiabbfccbcchdecfdicedhccdgczddcfbccgbaabdaazbdccbdcebdaybachdgcd',
    #     'thgtisytamnmetcytchdhczdhacdfazdaadddazbcacdfaabcaybeccbcazbbcadaczbdcydhadbbcedcczdecfdacadiacbccgdachdeacdaaybfcgbfaaddcydjcgbfcbdcaydacbbfchde',
    #     'mylbmegtyaqiceagafabcjahcaajceyfcbyecaydciaecgaeccaiaeygciadafyfceyfccajaaajaaadaeagaeajcjydaeabacaecbaiabakccahciygccadchacciygaaahcaaccgag',
    #     'ilmwessnmepbeccbachdbcybbcadechdacdddczbbacbbccdhazbdcybbaydjazbfaadeazbccddaccdacddacdbaccdbazdhchdacgdhaddaadbacedccbdicabeccbecebfcybead',
    #     'brsuefmsceyutaalisapstjzciahaaydceygafafcjaiadajcjakcdygchakceabafyecdydacabacajafagceajccajciaeadygceadacafacyfabakaeabaeaeaaaicbafccahcdacciakaeaecdad'
    # ]

    # Key: abcd
    ListOfCipherTexts = [
        'wfcueekvcpxhrffvawgbovtvemhrvftffbcfbbefgbgfadgdedffhbefjdifeddfddefdbgfbdkfibgdbdifcbfdadddbbgfibfdfdgdcdlfedjfidifhdgfgddfddjdcdkdabffabddddgdddiddbcdadlfgdh',
        'tikvitcvanroeugatdlfhddfhbgffbdfabhfdbddcbgffbedcbcdedgdcbddbdefadddddcfhbhdbdifcddfedjfadefibgdcdkfadlfebgfabcdfdkdfbefddcfjdkdfdffcbcfadfdfdlfe',
        'mzpdmfkvybukcfeiagedckejcbelcfchcccgcbcfcjegchegcdekafcicjefagchcfchcdelabelabefafeiafelckcfafedadegccekacemcdejcjcicdefcieecjciabejcbeechei',
        'imqyetwpmftdedgdadlfbdcdbdefedlfadhfddddbbgdbdgfhbddddcdbbcfjbddfbefebddcdhfadgfadhfadhdadgfbbdfhdlfadkfhbhfabhdadifcdffidededgdedidfdcdebh',
        'bswwegqucfcwtbenitersunbcjejabcfcfciagehckekaeelckemceciciemcfedagcgcecfadedadelageicfelcdelcjegaecicfefadehadchacemafedafegabekccehcdejceeecjemafegceef'
    ]

    DiscoveredKey = launch_brute_force_attack(ListOfCipherTexts)
    print('Discovered key from brute force attack: {}'.format(DiscoveredKey))
