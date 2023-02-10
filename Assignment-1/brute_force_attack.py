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


def verify_property_pi(text):
    plaintext = text[:-128]
    givenPiText = text[-128:]
    calculatedPiText = property_pi(plaintext)

    if givenPiText == calculatedPiText:
        return True
    else:
        return False


def is_key_valid(ciphertext, key):
    keyLength = len(key)
    decryptedPlainText = ''

    for i in range(len(ciphertext)):
        c_i = ord(ciphertext[i])
        k_i = ord(key[i % keyLength]) - 97
        p_i = chr((c_i - 97 - k_i) % 26 + 97)
        decryptedPlainText += p_i

    if verify_property_pi(decryptedPlainText):
        return True
    else:
        return False


def launch_brute_force_attack(listOfCipherTexts):
    charSet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    keyLength = 4
    for key_char_1 in charSet:
        for key_char_2 in charSet:
            for key_char_3 in charSet:
                for key_char_4 in charSet:
                    currentKey = key_char_1 + key_char_2 + key_char_3 + key_char_4
                    print('Checking key: {}'.format(currentKey))
                    currentKeyValidForCipherTexts = 0
                    for currentCipherText in listOfCipherTexts:
                        if not is_key_valid(currentCipherText, currentKey):
                            continue
                        else:
                            currentKeyValidForCipherTexts += 1
                            print('Key: {} is valid for ciphertext: {}'.format(currentKey, currentCipherText))
                    if currentKeyValidForCipherTexts == 5:
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
