#include <string>
using namespace std;

class RSAKey
{
protected:
	// Key components, in the order they should appear in the file
	// File may have only n and e, if it's only a public key
	// File may have only n, e, d if CRT components are not included
	string n;
	string e;
	string d;
	string p;
	string q;
	string dP;
	string dQ;
	string qInv;

	// key length in nibbles (hex digits)
	unsigned int keyLen;

	// key file will contain the components as hexidecimal strings
	bool ReadKeyFile(string keyFile, string kek = "", bool useECB = false);

public:
	// encrypt with public key, same as verification
	string EncryptRSA(string input, string keyFile = "");
	// decrypt with private key, same as signing; KEK only needed of keyfile is encrypted
	string DecryptRSA(string input, string keyFile = "", string kek = "", bool useECB = false);

	// encrypt with the public key, decrypt with the private key
	// sign with CRT components, verify with public key
	bool ValidateRSAKey(string keyFile, string kek = "", bool useECB = false);

};

