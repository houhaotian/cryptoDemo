#include <iostream>

#include <aes.h>  
#include <algorithm>
#include <vector>
#include <Hex.h>      // StreamTransformationFilter  
#include <string>  
#include <modes.h>


using namespace std;
using namespace CryptoPP;

#pragma comment( lib, "cryptlib.lib")

std::string ECB_AESEncryptStr(std::string sKey, const char *plainText)
{
    std::string outstr;

    //填key  
    SecByteBlock key(AES::MAX_KEYLENGTH);
    memset(key, 0x30, key.size());
    sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);


    AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

    ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);
    StreamTransformationFilter ecbEncryptor(ecbEncryption, new HexEncoder(new StringSink(outstr)));
    ecbEncryptor.Put((byte *)plainText, strlen(plainText));
    ecbEncryptor.MessageEnd();

    return outstr;
}

std::string ECB_AESDecryptStr(std::string sKey, const char *cipherText)
{
    std::string outstr;

    //填key  
    SecByteBlock key(AES::MAX_KEYLENGTH);
    memset(key, 0x30, key.size());
    sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

    ECB_Mode<AES >::Decryption ecbDecryption((byte *)key, AES::MAX_KEYLENGTH);

    HexDecoder decryptor(new StreamTransformationFilter(ecbDecryption, new StringSink(outstr)));
    decryptor.Put((byte *)cipherText, strlen(cipherText));
    decryptor.MessageEnd();

    return outstr;
}


int main()
{
    std::string plainText("hello world!");
    std::string keyWord("123456");
    std::string encrypttedString, decrypttedString;

    encrypttedString = ECB_AESEncryptStr(keyWord, plainText.c_str());
    decrypttedString = ECB_AESDecryptStr(keyWord, encrypttedString.c_str());

    std::cout << "encrypt" << std::endl << encrypttedString << std::endl;
    std::cout << "decrypt" << std::endl << decrypttedString << std::endl;
}
