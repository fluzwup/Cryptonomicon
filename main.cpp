#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <Flint/sha1.h>
#include <unistd.h>
using namespace std;
#include "main.h"
#include "DES.h"
#include "RSA.h"

// Converts two bytes of ASCII data representing a hexadecimal string into the binary
//  value it represents
unsigned char ByteFromStr(const char *input)
{
	unsigned char value = 0;
	switch(input[0])
	{
		case '0':
			break;
		case '1':
			value += 0x10;
			break;
		case '2':
			value += 0x20;
			break;
		case '3':
			value += 0x30;
			break;
		case '4':
			value += 0x40;
			break;
		case '5':
			value += 0x50;
			break;
		case '6':
			value += 0x60;
			break;
		case '7':
			value += 0x70;
			break;
		case '8':
			value += 0x80;
			break;
		case '9':
			value += 0x90;
			break;
		case 'A':
		case 'a':
			value += 0xA0;
			break;
		case 'B':
		case 'b':
			value += 0xB0;
			break;
		case 'C':
		case 'c':
			value += 0xC0;
			break;
		case 'D':
		case 'd':
			value += 0xD0;
			break;
		case 'E':
		case 'e':
			value += 0xE0;
			break;
		case 'F':
		case 'f':
			value += 0xF0;
			break;
		default:
			throw input[0];
	}

	switch(input[1])
	{
		case '0':
			break;
		case '1':
			value += 0x1;
			break;
		case '2':
			value += 0x2;
			break;
		case '3':
			value += 0x3;
			break;
		case '4':
			value += 0x4;
			break;
		case '5':
			value += 0x5;
			break;
		case '6':
			value += 0x6;
			break;
		case '7':
			value += 0x7;
			break;
		case '8':
			value += 0x8;
			break;
		case '9':
			value += 0x9;
			break;
		case 'A':
		case 'a':
			value += 0xA;
			break;
		case 'B':
		case 'b':
			value += 0xB;
			break;
		case 'C':
		case 'c':
			value += 0xC;
			break;
		case 'D':
		case 'd':
			value += 0xD;
			break;
		case 'E':
		case 'e':
			value += 0xE;
			break;
		case 'F':
		case 'f':
			value += 0xF;
			break;
		default:
			throw (char)input[1];
	}

	return value;
}


// converts binary data into a hexadecimal string (assumes output has been pre-sized)
void bin2hex(const unsigned char *input, int len, char *output) 
{
	int i;
	for(i = 0; i < len; ++i)
		sprintf(&output[i * 2], "%02X", input[i]);
	output[i * 2] = (char)0;
	return;
}

// checks to see if a string consists of hexadecimal digits, returns false if not
bool checkHex(const char *input)
{
	int len = strlen(input);

	try
	{
		for(int i = 0; i < len; i += 2)
		{
			ByteFromStr(&input[i]);
		}
	}
	catch(char c)
	{
		return false;
	}
	return true;
}	

string LoadKeyFromTable(string key)
{
	string keyValue = "";
	string name = "";

	bool found = false;
	FILE *fp = fopen("keyTable.txt", "r");

	char line[4096];
	while(fp != NULL && !feof(fp) && !found)
	{
		fgets(line, 4096, fp);
		name = strtok(line, " ");
		keyValue = strtok(NULL, "\n");

		if(key == name)
			found = true;
	}
	
	if(found ) return keyValue;

	printf("Key %s not found in keyTable.txt!\n\n", key.c_str());
	exit(-1);

	return "";
}

// convert a C string to binary, output length
void hex2bin(const char *input, unsigned char* output, int &len) 
{
	len = strlen(input);

	// must ben an even number of characters
	if(len % 2)
		throw (const char *)"Hex input must be an even number of digits";

	for(int i = 0; i < len; i += 2)
	{
		output[i / 2] = ByteFromStr(&input[i]);
	}
	len /= 2;
	return;
}

// convert a given number of characters to binary
void hex2bin(const char *input, int len, unsigned char* output) 
{
	string tmp = input;
	tmp.resize(len);
	len = len * 2;
	hex2bin(tmp.c_str(), output, len);
}

// returns the minimum of two integers
inline int min(int a, int b)
{
	return a > b ? b : a;
}

// generates hex data, length is hex digits
string GenerateRandom(int length)
{
	FILE *fd = fopen("/dev/urandom", "r");
	if(fd == NULL) throw;

	size_t count = 0;
	string random;
	random.resize(length, '0');
	char *output = (char *)random.c_str();

	while(count < length)
	{
		unsigned char buffer[2048];

		// convert from hex digits to bytes
		size_t bytesToRead = min(4096, length - count) / 2;
		size_t bytesRead = fread(buffer, 1, bytesToRead, fd);
		if(bytesRead < bytesToRead) 
		{
			fclose(fd);
			printf("Ran out of entropy creating random numbers!\n");
			throw;
		}
		// convert from binary to hex string
		bin2hex(buffer, bytesRead, &output[count * 2]);
		// count is in hex digits
		count += bytesRead * 2;
	}
	fclose(fd);

	return random;
}

// count the ones in a hex byte
int CountOnes(const char *input)
{
	int count = 0;
	for(int i = 0; i < 2; ++i)
	{
		switch(input[i])
		{
			case '0':
				break;
			case '1':
				count += 1;
				break;
			case '2':
				count += 1;
				break;
			case '3':
				count += 2;
				break;
			case '4':
				count += 1;
				break;
			case '5':
				count += 2;
				break;
			case '6':
				count += 2;
				break;
			case '7':
				count += 3;
				break;
			case '8':
				count += 1;
				break;
			case '9':
				count += 2;
				break;
			case 'A':
			case 'a':
				count += 2;
				break;
			case 'B':
			case 'b':
				count += 3;
				break;
			case 'C':
			case 'c':
				count += 2;
				break;
			case 'D':
			case 'd':
				count += 3;
				break;
			case 'E':
			case 'e':
				count += 3;
				break;
			case 'F':
			case 'f':
				count += 4;
				break;
			default:	// not a valid hex digit, return error
				printf("Error, found a non-hex digit when calculating parity\n\n");
				return -1;
				break;
		}
	}

	return count;
}

// determine parity by counting the number of 1s in the binary version of a hex string
int CheckParity(const char *input)
{
	int count = 0;
	int i = 0;
	bool odd = true;
	while(input[i] != 0)
	{
		if(CountOnes(&input[i]) % 2 != 1)
		{
			printf("Byte %i is even parity.\n", i / 2);
			odd = false;
		}
		i += 2;
	}

	// only if all bytes are odd does the key count as odd parity
	return odd;
}

// adjust parity so that each byte has odd parity
void AdjustParity(char *input)
{
	int count = 0;
	int i = 0;
	bool odd = true;
	//printf("Adjusting parity of %s ", input);
	while(input[i] != 0)
	{
		int oneCount = CountOnes(&input[i]);
	
		if(oneCount % 2 != 1)
		{
			//printf("Byte %c%c has %i ones, forcing odd", input[i], input[1 + i], oneCount);
			// since this is hex, we xor the value of the byte with 1 to flip
			//  its value, altering the parity of the byte 
			unsigned char hex = ByteFromStr(&input[i]);
			hex ^= 0x01;
//			hex = (hex & 0xFE) | ((!hex) & 0x01);
			char output[3];
			bin2hex(&hex, 1, output);
			input[i] = output[0];
			input[i + 1] = output[1];
			//printf(" new byte %c%c\n", input[i], input[i + 1]);
		}
		i += 2;
	}
	//printf(" to %s\n", input);
}

// pad a hex string to 16 characters (8 bytes in binary)
void padData(string &data, string pad)
{
	int newLen = ((data.length() + 15) / 16) * 16;

	if(newLen == data.length()) return;

	do
	{
		data += pad.substr(0, 2);
	} while(data.length() < newLen);

	printf("Data padded with 0x%s to length %i\n", pad.substr(0, 2).c_str(), data.length());
}

// Encrypts binary data with 3DES
bool EncryptDESbin(unsigned char *in, int inLen, unsigned char *key, int kLen, bool useECB, unsigned char *out)
{
	if(useECB)
		encryptECB(key, kLen, in, inLen, out);
	else
		encryptCBC(key, kLen, in, inLen, out);
}

// Decrypts binary data with 3DES
bool DecryptDESbin(unsigned char *in, int inLen, unsigned char *key, int kLen, bool useECB, unsigned char *out)
{
	if(useECB)
		decryptECB(key, kLen, in, inLen, out);
	else
		decryptCBC(key, kLen, in, inLen, out);

}

// Encrypts ASCII hexadecimal data with 3DES
bool EncryptDES(const char *input, const char *key, bool useECB, char *output)
{
	// convert from hex strings to binary
	unsigned char in[4096];
	unsigned char out[4096];
	unsigned char k[64];
	int len;
	int klen;
	
	hex2bin(input, in, len);
	hex2bin(key, k, klen);
	if(useECB)
		encryptECB(k, klen, in, len, out);
	else
		encryptCBC(k, klen, in, len, out);

	bin2hex(out, len, output);
}

// Decrypts ASCII hexadecimal data with 3DES
bool DecryptDES(const char *input, const char *key, bool useECB, char *output)
{
	// convert from hex strings to binary
	unsigned char in[4096];
	unsigned char out[4096];
	unsigned char k[64];
	int len;
	int klen;
	
	hex2bin(input, in, len);
	hex2bin(key, k, klen);
	if(useECB)
		decryptECB(k, klen, in, len, out);
	else
		decryptCBC(k, klen, in, len, out);

	bin2hex(out, len, output);

}

// Generates the SHA1 hash of a string of ASCII hexadecimal data
void FindSHA1(string data)
{
		unsigned char binary[2048];
		int len;
		unsigned char hash[20];

		hex2bin(data.c_str(), binary, len);	

		sha1_l(hash, binary, len);

		char output[41];

		bin2hex(hash, 20, output);

		printf("SHA1 is %s\n", output);
}

// does an in-place decryption of a string of ASCII hexadecimal data
void DecryptInPlace(string kek, bool useECB, char *buffer)
{
	char output[4096];
	DecryptDES(buffer, kek.c_str(), useECB, output);
	strcpy(buffer, output);
}

// generates the CVV/CVC hash for the given data
string GenerateCVC(string key, string PAN, string date, string serviceCode)
{
	unsigned char block[16] = {0};
	unsigned char step3[16] = {0};
	unsigned char step4[16] = {0};
	unsigned char step5[16] = {0};
	unsigned char step6[16] = {0};
	unsigned char cvkA[32];
	unsigned char cvkB[32];

	int klen = 32;

	// split key into A and B
	hex2bin(key.c_str(), cvkA, klen);
	hex2bin(key.c_str() + key.length() / 2, cvkB, klen);
	
	// concatenate PAN, date, and service code
	string tmp = PAN + date + serviceCode;

	// take the 4 least signficant bits of each character
	for(int i = 0; i < tmp.length(); i += 2)
	{
		int c0 = (tmp[i] != 0) ? tmp[i] - '0' : 0;
		int c1 = (tmp[i + 1] != 0) ? tmp[i + 1] - '0' : 0;
		block[i / 2] = (c0 << 4) + c1;
	}

	// encrypt left half with key A
	encryptECB(cvkA, klen, block, 8, step3);

	// XOR step3 output with block 2
	for(int i = 0; i < 8; ++i)
		step3[i] ^= block[8 + i];
	
	// encrypt output with key A
	encryptECB(cvkA, klen, step3, 8, step4);
	
	// decrypt output with key B
	decryptECB(cvkB, klen, step4, 8, step5);

	// encrypt output with key A
	encryptECB(cvkA, klen, step5, 8, step6);

	char hex[64] = {0};
	bin2hex(step6, 8, hex);
	string sifted = "";

	for(int i = 0; i < strlen(hex); ++i)
		if(hex[i] >= '0' && hex[i] <= '9')
			sifted += hex[i];

	for(int i = 0; i < strlen(hex); ++i)
	{
		if(hex[i] >= 'A' && hex[i] <= 'F')
			sifted += hex[i] - 'A' + '0';
		if(hex[i] >= 'a' && hex[i] <= 'f')
			sifted += hex[i] - 'a' + '0';
	}

	return sifted.substr(0, 3);
}

// Generates the CVV/CVC, iCVV/iCVC, and CVV2/CVC2 from the given data
void GenerateCVCs(string key, string PAN, string data)
{
	string CVC = GenerateCVC(key, PAN, data.substr(0, 4), data.substr(4, 3));
	// use 999 as service code for iCVC
	string iCVC = GenerateCVC(key, PAN, data.substr(0, 4), "999");
	// use 000 as service code, swap year/month for CVC2
	string CVC2 = GenerateCVC(key, PAN, data.substr(2, 2) + data.substr(0, 2), "000");

	printf("CVC/CVV is %s, iCVC/iCVV is %s, CVC2/CVV2 is %s\n", 
		CVC.c_str(), iCVC.c_str(), CVC2.c_str());	
}

// keep just the least significant nibble of each byte of ASCII; effectively turns 0-9 in ASCII
//  to 0-9 in binary, or BCD
void Pack(string source, unsigned char *packed, int *len) 
{
   char digit;

   int i = 0;
   int k = 0;
   int j = source.length();

   for (i = 0; i < j; i++) {
      digit = source.at(i) & 0x0f;

      if (i % 2 == 0) {
         packed[k] = (unsigned char) (digit << 4);
      } else {
         packed[k] = (unsigned char) (packed[k] | digit);
         k++;
      }
   }

   if ((i - 1) % 2 == 0) k++;
   *len = k;

   return;
}

// data is last 14 of PAN plus 2 digit sequence number
string GenerateSKD(string key, string data)
{
	// MasterCard proprietary SKD method, M/Chip 4 Version 1.1, 
	// Security & Key Management, 7-4
	// data contains R, which is defined as the application transaction
	// counter (ATC) + '0000' + the unpredictable number of the transaction
	
	int len;
	if(data.length() < 16)
	{
		printf("Value of R must be 8 bytes (16 hex digits).\n\n");
		return "";
	}
	unsigned char k[64];
	int klen;
	hex2bin(key.c_str(), k, klen);

	// convert 8 byte R to binary twice, once for left and once for right
	unsigned char L[8];
	unsigned char R[8];
	hex2bin(data.c_str(), L, len);
	hex2bin(data.c_str(), R, len);

	// replace 3rd byte of each with F0 and 0F 
	L[2] = 0xF0;
	R[2] = 0x0F;

	unsigned char outL[8];
	unsigned char outR[8];
	// DES encrypt the right land left parts
	encryptECB(k, klen, L, 8, outL); 
	encryptECB(k, klen, R, 8, outR); 

	// convert to hex, and concatenate
	char SKDL[17];
	char SKDR[17];
	bin2hex(outL, 8, SKDL);
	bin2hex(outR, 8, SKDR);

//	printf("SKD is %s%s\n\n", SKDL, SKDR);
	return (string)SKDL + (string)SKDR;
}

// XORs two ASCII strings containing hexadecimal data together
string StringXOR(string one, string two)
{
   char output[4096] = {0};

   if(one.length() != two.length()) return output;

   unsigned char bin1[1024];
   unsigned char bin2[1024];
   unsigned char bin3[1024];
   int len;

   hex2bin(one.c_str(), bin1, len);
   hex2bin(two.c_str(), bin2, len);

   for(int i = 0; i < one.length(); ++i)
   {
      bin3[i] = bin1[i] ^ bin2[i];
   }

   bin2hex(bin3, len, output);

   return output;
}

// Generates a uniquely derived key
string GenerateUDK(string key, string PAN, string Sequence)
{
/*
      M/Chip 4 Version 1.1 Security & Key Management June 2006
      Section 7, ICC Master Key Derivation
      This also works for Visa UDKs
*/      
	if(Sequence.length() < 2) Sequence = "0" + Sequence;
	string Y = PAN + Sequence;
	string antiY;
	char Z[64] = {0};

	Y = Y.substr(Y.length() - 16, 16);
	antiY = StringXOR(Y, "FFFFFFFFFFFFFFFF");
	
	EncryptDES(Y.c_str(), key.c_str(), true, Z);
	EncryptDES(antiY.c_str(), key.c_str(), true, &Z[16]);

	AdjustParity(Z);

//	printf("Derived key is %s\n", Z);
	return Z;
}

// This assumes the mandatory "80" has been added already, for CVN methods other than Visa CVN 10
string GenerateAC(string key, string data, string pad)
{
	// Application Cryptogram, M/Chip 4 Version 1.1, 
	// Security & Key Management, 4-1
	// EMV 4.3 book 2 annex A1.2.1
	// Visa Integrated Circuit Card Specification Version 1.5, 1.6 appendix D
	// CVN 10 calls for padding with all zeros, CVN 18 uses 80 padding like MC and EMV

	int len;
	if(key.length() < 32)
	{
		printf("Key length is too short, must be double length DES key (32 hex digits)\n\n");
		return string("");
	}
	// break the key into two single DES keys, Left and Right
	unsigned char L[8]; 
	unsigned char R[8]; 
	hex2bin(key.substr(0, 16).c_str(), L, len);
	hex2bin(key.substr(16, 16).c_str(), R, len);

	printf("Split key, %s and %s\n", key.substr(0, 16).c_str(), key.substr(16, 16).c_str());

	int blockOffset = 0;
	// start output as zeros, so it can be XORed with first data block
	unsigned char output[8] = {0};
	unsigned char input[8] = {0};
	char result[17];
	
	while(blockOffset < data.length())
	{
		// break data into 8 byte (16 hex digit) blocks
		string sD = data.substr(blockOffset, 16);
		blockOffset += 16;

		while(sD.length() < 16)
			sD += string("00");

		printf("Data block %i, 0x%s\n", blockOffset / 16, sD.c_str());
		unsigned char D[8];
		hex2bin(sD.c_str(), D, len);

		// XOR previous output with D to make new input
		for(len = 0; len < 8; ++len)
			input[len] = output[len] ^ D[len];
		
		bin2hex(input, 8, result);
		printf("XORed 0x%s ", result);

		// DES encrypt output with left key; cbc or ecb are the same at this length
		encryptECB(L, 8, input, 8, output);

		bin2hex(output, 8, result);
		printf("Encrypted 0x%s\n", result);

	}
	printf("Last block, performing final decrypt/encrypt operation\n");
	
	// right key decrypt previous output into final input
	decryptECB(R, 8, output, 8, input);
	// left key encrypt final input into final output
	encryptECB(L, 8, input, 8, output);

	// convert binary to hex
	bin2hex(output, 8, result);

	return result;
}

// This prints out all the PINs that match a given PIN verification value
void GenerateAllPVVs(string PAN, string key, string targetPVV)
{
	unsigned char pvkA[32];
	unsigned char pvkB[32];
	int klen = 32;

	// split key into A and B
	hex2bin(key.c_str(), pvkA, klen);
	hex2bin(key.c_str() + key.length() / 2, pvkB, klen);

	for(int pin = 0; pin < 10000; ++pin)
	{
		unsigned char block[16] = {0};
		unsigned char step3[16] = {0};
		unsigned char step4[16] = {0};
		unsigned char step5[16] = {0};
		char PIN[16];

		sprintf(PIN, "%04i", pin);

		// concatenate PAN, PVK index (always 1), and PIN
		string tmp = PAN.substr(4, 11) + "1" + PIN;

		// take the 4 least signficant bits of each character
		for(int i = 0; i < tmp.length(); i += 2)
		{
			int c0 = (tmp[i] != 0) ? tmp[i] - '0' : 0;
			int c1 = (tmp[i + 1] != 0) ? tmp[i + 1] - '0' : 0;
			block[i / 2] = (c0 << 4) + c1;
		}

		// encrypt with key A
		encryptECB(pvkA, klen, block, 8, step3);

		// decrypt output with key B
		decryptECB(pvkB, klen, step3, 8, step4);
		
		// encrypt output with key A
		encryptECB(pvkA, klen, step4, 8, step5);

		// sift through, skipping >9 digits
		char hex[64] = {0};
		bin2hex(step5, 8, hex);
		string sifted = "";

		for(int i = 0; i < strlen(hex); ++i)
			if(hex[i] >= '0' && hex[i] <= '9')
				sifted += hex[i];

		// Convert the >= A digits to decimal
		for(int i = 0; i < strlen(hex); ++i)
		{
			if(hex[i] >= 'A' && hex[i] <= 'F')
				sifted += hex[i] - 'A' + '0';
			if(hex[i] >= 'a' && hex[i] <= 'f')
				sifted += hex[i] - 'a' + '0';
		}

		// grab the first four digits
		string PVV = sifted.substr(0, 4);
		if(targetPVV == "")
			printf("PIN %s PVV is %s\n", PIN, PVV.c_str());
		else
		{
			if(targetPVV == PVV)
				printf("PIN %s matches target PVV\n", PIN);
		}

	}
	return;
}

// This generates a PIN verification value from a given PIN
void GeneratePVV(string PAN, string PIN, string key)
{
	unsigned char block[16] = {0};
	unsigned char step3[16] = {0};
	unsigned char step4[16] = {0};
	unsigned char step5[16] = {0};
	unsigned char pvkA[32];
	unsigned char pvkB[32];

	int klen = 32;

	// split key into A and B
	hex2bin(key.c_str(), pvkA, klen);
	hex2bin(key.c_str() + key.length() / 2, pvkB, klen);
	
	// concatenate PAN, PVK index (always 1), and PIN
	string tmp = PAN.substr(4, 11) + "1" + PIN;

	// take the 4 least signficant bits of each character
	for(int i = 0; i < tmp.length(); i += 2)
	{
		int c0 = (tmp[i] != 0) ? tmp[i] - '0' : 0;
		int c1 = (tmp[i + 1] != 0) ? tmp[i + 1] - '0' : 0;
		block[i / 2] = (c0 << 4) + c1;
	}

	// encrypt with key A
	encryptECB(pvkA, klen, block, 8, step3);

	// decrypt output with key B
	decryptECB(pvkB, klen, step3, 8, step4);
	
	// encrypt output with key A
	encryptECB(pvkA, klen, step4, 8, step5);

	// sift through, skipping >9 digits
	char hex[64] = {0};
	bin2hex(step5, 8, hex);
	string sifted = "";

	for(int i = 0; i < strlen(hex); ++i)
		if(hex[i] >= '0' && hex[i] <= '9')
			sifted += hex[i];

	// Convert the >= A digits to decimal
	for(int i = 0; i < strlen(hex); ++i)
	{
		if(hex[i] >= 'A' && hex[i] <= 'F')
			sifted += hex[i] - 'A' + '0';
		if(hex[i] >= 'a' && hex[i] <= 'f')
			sifted += hex[i] - 'a' + '0';
	}

	// grab the first four digits
	printf("PVV is %s\n", sifted.substr(0, 4).c_str());
	return;
}

int main(int argc, char **argv)
{
	bool encrypt = false;
	bool decrypt = false;
	bool sign = false;
	bool useECB = false;
	bool findKCV = false;
	bool findSHA1 = false;
	bool checkCertificate = false;
	bool checkRSAKey = false;
	bool useRSA = false;
	bool cvc = false;
	bool createPVV = false;
	bool generateAC = false;
	bool generateAC_Visa_CVN10 = false;
	bool arpc1 = false;
	bool arpc2 = false;
	bool skd = false;
	bool udk = false;
	bool checkParity = false;
	bool export3components = false;
	string key = "";
	string data = "";
	string PIN = "";
	string PAN = "";
	string KCV = "";
	string kek = "";
	string name = "";
	string PVV = "";
	string ARQC = "";
	string ARPC = "";
	string seq = "";
	string ATC = "";
	string unp = "";


	if(argc == 1)
	{
		printf("Usage:\n"
		"\tencrypt [ecb|cbc] key=Key data=HexString\n"
		"\tdecrypt [ecb|cbc] key=Key data=HexString\n"
		"\tencryptRSA key=keyfile data=HexString\n"
		"\tdecryptRSA key=keyfile data=HexString\n"
		"\tencrypt key=Key PIN=XXXX PAN=XXXXXXXXXXXXXXXX\n"
		"\tdecrypt key=Key PIN=HexPINBlock PAN=XXXXXXXXXXXXXXXX\n"
		"\tcheckCertificate key=keyfile data=XXXXXX...\n"
		"\tkcv key=Key [kek=Kek]\n"
		"\tsha1 data=HexString\n" 
		"\tcheckRSAKey key=keyfile [kek=Key] [ecb|cbc] (omit filename for format info)\n"
		"\tcreatePVV key=keyName PAN=XXXXXXXXXXXXXXXX [PIN=XXXX | PVV=XXXX]\n"
		"\tcvc key=CVKname PAN=XXXXXXXXXXXXXXXX data=YYMMSVC (data is date and 3 service code)\n"
		"\tudk key=MDK PAN=XXXXXXXXXXXXXXX seq=XX (seq is sequence number)\n"
		"\tskd key=UDK ATC=XXXX [unp=XXXXXXXX]\n"
		"\t    (EMV 2000 uses ATC, M/Chip uses ATC and unpredictable number)\n"
		"\tgenerateAC key=SessionKey data=DataBlocks (uses 80... padding, session key)\n"
		"\tgenerateAC key=IMK PAN=XXX seq=XX ATC=XXXX [unp=XXXXXXXX] data=DataBlocks\n"
		"\tgenerateAC_Visa_CVN10 key=UDK data=DataBlocks (uses 00.. padding, direct UDK)\n"
		"\tgenerateAC_Visa_CVN10 key=MDK PAN=XXX seq=XX data=DataBlocks\n"
		"\tgetARPC_M1 key=UDK ARQC=XXXXXXXXXXXXXXXX data=XXXX (CSU or ASCII field 39)\n"
		"\tgetARPC_M2 key=SKD ARQC=XXXXXXXXXXXXXXXX data=XXXX (CSU + proprietary auth data)\n"
		"\tgetRC key=UDK ARQC=XXXXXXXXXXXXXXXX ARPC=XXXXXXXXXXXXXXXX\n"
		"\tcheckParity key=Key\n"
		"\texport3components key=Key\n\n");
		return 0;
	}

	for(int i = 1; i < argc; ++i)
	{
		if(strcmp(argv[i], "decrypt") == 0)
			decrypt = true;
		else if(strcmp(argv[i], "decryptRSA") == 0)
		{
			decrypt = true;
			useRSA = true;
		}
		else if(strcmp(argv[i], "encrypt") == 0)
			encrypt = true;
		else if(strcmp(argv[i], "encryptRSA") == 0)
		{
			encrypt = true;
			useRSA = true;
		}
		else if(strcmp(argv[i], "ecb") == 0)
			useECB = true;
		else if(strcmp(argv[i], "cbc") == 0)
			useECB = false;
		else if(strncmp(argv[i], "key=", 4) == 0)
			key = argv[i] + 4;
		else if(strncmp(argv[i], "data=", 5) == 0)
			data = argv[i] + 5;
		else if(strncmp(argv[i], "PIN=", 4) == 0)
			PIN = argv[i] + 4;
		else if(strncmp(argv[i], "PAN=", 4) == 0)
			PAN = argv[i] + 4;
		else if(strncmp(argv[i], "kcv=", 4) == 0)
			KCV = argv[i] + 4;
		else if(strcmp(argv[i], "kcv") == 0)
			findKCV = true;
		else if(strcmp(argv[i], "sha1") == 0)
			findSHA1 = true;
		else if(strcmp(argv[i], "checkCertificate") == 0)
			checkCertificate = true;
		else if(strcmp(argv[i], "checkRSAKey") == 0)
			checkRSAKey = true;
		else if(strcmp(argv[i], "cvc") == 0)
			cvc = true;
		else if(strncmp(argv[i], "kek=", 4) == 0)
			kek = argv[i] + 4;
		else if(strncmp(argv[i], "name=", 4) == 0)
			name = argv[i] + 5;
		else if(strcmp(argv[i], "createPVV") == 0)
			createPVV = true;
		else if(strncmp(argv[i], "PVV=", 4) == 0)
			PVV = argv[i] + 4;
		else if(strcmp(argv[i], "generateAC") == 0)
			generateAC = true;
		else if(strcmp(argv[i], "generateAC_Visa_CVN10") == 0)
			generateAC_Visa_CVN10 = true;
		else if(strcmp(argv[i], "getARPC_M1") == 0)
			arpc1 = true;
		else if(strcmp(argv[i], "getARPC_M2") == 0)
			arpc2 = true;
		else if(strcmp(argv[i], "getRC") == 0)
			arpc1 = true;
		else if(strncmp(argv[i], "ARQC=", 5) == 0)
			ARQC = argv[i] + 5;
		else if(strncmp(argv[i], "ARPC=", 5) == 0)
			ARPC = argv[i] + 5;
		else if(strcmp(argv[i], "skd") == 0)
			skd = true;
		else if(strcmp(argv[i], "udk") == 0)
			udk = true;
		else if(strncmp(argv[i], "seq=", 4) == 0)
			seq = argv[i] + 4;
		else if(strncmp(argv[i], "ATC=", 4) == 0)
			ATC = argv[i] + 4;
		else if(strncmp(argv[i], "unp=", 4) == 0)
			unp = argv[i] + 4;
		else if(strcmp(argv[i], "checkParity") == 0)
			checkParity = true;
		else if(strcmp(argv[i], "export3components") == 0)
			export3components = true;
		else
			printf("Unknown argument %s ignored.\n", argv[i]);
	}

	// Check key and kek values for functions that use DES keys.  If they are hex values, then
	//  they are clear keys.  If they are not hex values, then they are named keys, so pull the
	//  values from keyTable.txt.
	if(!checkRSAKey && !useRSA && !checkCertificate)
	{
		if(!checkHex(key.c_str()))
			key = LoadKeyFromTable(key);
	}
	// kek is always a DES key
	if(!checkHex(kek.c_str()))
		kek = LoadKeyFromTable(key);
	
	
	if(checkRSAKey)
	{
		// assume public key only
		bool hasPrivateKey = false;

		if(key == "")
		{
			printf("Keys are provided in a text file with one line per field.  Values should be in hexidecimal (upper or lower case).\n\n"
				"\tn    Public modulus\n"
				"\te    Public exponent\n"
				"\td    Private exponent\n"
				"\tp    Private prime 1\n"
				"\tq    Private prime 2\n"
				"\tdP   Private exponent 1\n"
				"\tdQ   Private exponent 2\n"
				"\tqIn  Private coefficient\n\n"
				"If only a public key is to be imported, then only provide the first two lines.\n\n");
			return 0;
		}

		try
		{
			RSAKey rsa;
			bool ret = rsa.ValidateRSAKey(key, kek, useECB);
	
			if(ret) 
				printf("RSA key is valid.\n\n");
			else
				printf("RSA key is NOT valid.\n\n");
		}
		catch(const char *e)
		{
			printf("Exception:  %s\n", e);
		}

		return 0;
	}

	if(checkCertificate)
	{
		if(data == "")
		{		
			printf("Certificate must be passed in with data=XXXX...\n");
			return -1;
		}
		if(key == "")
		{		
			printf("Certificate decryption requires a key file\n");
			return -1;
		}

		string certificate = "";
		try
		{
			RSAKey rsa;
			certificate = rsa.EncryptRSA(data, key);
		}
		catch(const char *e)
		{
			printf("Exception:  %s\n", e);
		} 
		int len = certificate.length();

		printf("Raw decrypted data:\n%s\n", certificate.c_str());

		if(certificate.substr(0, 2) == "6A" && certificate.substr(len - 2, 2) == "BC")
		{
			printf("Certificate appears to be complete and valid\n");
		}
		else
		{
			printf("Certificate not valid.\n");
			return 0;
		}

		int offset = 2;
		int type = strtoul(certificate.substr(offset, 2).c_str(), NULL, 16); offset += 2;
		printf("Certificate, type 0x%02x:\n", type);

		int temp = 0;
		switch(type)
		{
			case 0x02:
			case 0x11:
				printf("Issuer ID: %s\n", certificate.substr(offset, 8).c_str()); offset += 8;
				printf("Expiration date: %s\n", certificate.substr(offset, 4).c_str()); offset += 4;
				printf("Serial number: %s\n", certificate.substr(offset, 6).c_str()); offset += 6;
				printf("Hash algorithm: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Public key algorithm: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Public key length: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Exponent length: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				temp = len - offset - 42;
				printf("Public key: %s\n", certificate.substr(offset, temp).c_str()); offset += temp;
				printf("Hash: %s\n", certificate.substr(offset, 40).c_str());
				break;

			case 0x03:
				printf("Hash algorithm: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Data Authentication Code: %s\n", certificate.substr(offset, 4).c_str()); offset += 4;
				temp = len - offset - 42;
				printf("Pad pattern: %s\n", certificate.substr(offset, temp).c_str()); offset += temp;
				printf("Hash: %s\n", certificate.substr(offset, 40).c_str());
				break;

			case 0x04:
				printf("PAN: %s\n", certificate.substr(offset, 20).c_str()); offset += 20;
				printf("Expiration date: %s\n", certificate.substr(offset, 4).c_str()); offset += 4;
				printf("Serial number: %s\n", certificate.substr(offset, 6).c_str()); offset += 6;
				printf("Hash algorithm: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Public key algorithm: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Public key length: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				printf("Exponent length: %s\n", certificate.substr(offset, 2).c_str()); offset += 2;
				temp = len - offset - 42;
				printf("Public key: %s\n", certificate.substr(offset, temp).c_str()); offset += temp;
				printf("Hash: %s\n", certificate.substr(offset, 40).c_str());
				break;

			default:
				printf("Decomposition of certificate not supported.\n");
		}

		return 0;
	}
	if(findSHA1)
	{
		if(data == "")
		{
			printf("No data specified!  Provide hexideciaml string with data.\n");
			return -1;
		}

		FindSHA1(data);

		return 0;
	}

	if(key == "")
	{
		printf("No key specified!\n");
		return -1;
	}

	if(createPVV)
	{
		if(PAN == "")
		{
			printf("No PAN specified\n");
			return -1;
		}
		if(PIN == "")
		{
			GenerateAllPVVs(PAN, key, PVV);
			return 0;
		}

		GeneratePVV(PAN, PIN, key);

		return 0;
	}

	if(cvc)
	{
		if(data == "") 
		{
			printf("Must supply expiration data and service code in data field.\n");
			return -1;
		}
//		GenerateCVVs(key, PAN, data);
		GenerateCVCs(key, PAN, data);
		return 0;
	}

	// generate MasterCard session key using SKD method
	if(skd)
	{
		if(ATC == "")
		{
			printf("No data specified!  Provide ATC and, for M/Chip, unpredictable number.\n");
			return -1;
		}

		if(unp == "") unp = "00000000";
		string R = ATC + "0000" + unp;

		string SKD = GenerateSKD(key, R.c_str());
		printf("Session key is %s\n", SKD.c_str());
		return 0;
	}

	if(generateAC || generateAC_Visa_CVN10)
	{
		if(data == "")
		{
			printf("No data specified!  Provide hexidecimal string with supplied by terminal.\n");
			return -1;
		}

		// All but CVN 10 for Visa require an "80" be appended to the end of the transaction data, and
		// then fill to an 8 byte multiple with "00".  Some card test systems will put the "80" on the 
		// end of the transaction data they report, so warn the user if there's already an "80" on the
		// end so they can remove it if needed
		if(generateAC)
		{
			// check data
			if(data.substr(data.length() - 2, 2) == "80")
				printf("Warning:  transaction data ends in 0x80, so this may add redundant padding!\n");
			data += "80";
		}

		// if we have PAN, then assume we're given a master key and need to derive the UDK and/or session key
		if(PAN != "")
		{
			// all methods need a UDK
			if(seq == "")
			{
				printf("Provide sequence number.\n");
				return -1;
			}

			string UDK = GenerateUDK(key, PAN, seq);
			printf("Derived key is %s\n", UDK.c_str());

			if(generateAC_Visa_CVN10)
			{
				printf("Cryptogram is %s\n\n", GenerateAC(UDK, data, "00").c_str());
				return 0;
			}

			string R = ATC + "0000";
			if(unp == "")
				R += "00000000";
			else
				R += unp;

			// All but Visa CVN 10 need a session key
			string SKD = GenerateSKD(UDK, R);
			printf("Session key is %s\n", SKD.c_str());
			
			printf("Cryptogram is %s\n\n", GenerateAC(SKD, data, "00").c_str());
			return 0;
		}
		
		// Visa CVN 10 skips the "80", but all methods pad to an even mulitple of 8 bytes with "00"
		printf("ARQC is %s\n", GenerateAC(key, data, "00").c_str());
		return 0;
	}

	if(arpc1)
	{
		// check sizes
		if(ARQC.length() != 16)
		{
			printf("ARQC must be 16 hex digits in length\n");
			return -1;
		}
		if(key.length() != 32)
		{
			printf("UDK must be 32 hex digits in length\n");
			return -1;
		}
		// if we have the response code, it must be 4 digits
		if(data.length() != 4 && data.length() != 0)
		{
			printf("Response code must be 4 hex digits in length\n");
			return -1;
		}
		if(ARPC.length() != 16 && ARPC.length() != 0)
		{
			printf("ARPC must be 16 hex digits in length\n");
			return -1;
		}

		// split UDK into left and right halves
		string left = key.substr(0, 16);
		string right = key.substr(16, 16);

		if(data.length() == 4)
		{
			// XOR data, left justifed, with ARQC
			string combined = StringXOR(data + "000000000000", ARQC);
	
			char block1[32] = {0};
			char block2[32] = {0};
			strcpy(block1, combined.c_str());
			EncryptDES(block1, left.c_str(), true, block2);
			DecryptDES(block2, right.c_str(), true, block1);
			EncryptDES(block1, left.c_str(), true, block2);
	
			printf("ARPC is %s\n", block2);
			return 0;
		}

		if(ARPC.length() == 16)
		{
			// reverse the ARPC process to extract the response code
			char block1[32] = {0};
			char block2[32] = {0};
			strcpy(block1, ARPC.c_str());
			DecryptDES(block1, left.c_str(), true, block2);
			EncryptDES(block2, right.c_str(), true, block1);
			DecryptDES(block1, left.c_str(), true, block2);

			string rc = StringXOR(block2, ARQC);	

			printf("Response code is %s\n", rc.c_str());
			return 0;

		}
	}

	if(arpc2)
	{
		// check sizes
		if(ARQC.length() != 16)
		{
			printf("ARQC must be 16 hex digits in length\n");
			return -1;
		}
		if(key.length() != 32)
		{
			printf("SKD must be 32 hex digits in length\n");
			return -1;
		}

		// split UDK into left and right halves
		string left = key.substr(0, 16);
		string right = key.substr(16, 16);

		// concatenate data (EMV book 2 section 8.2.2)
		// append "80" and pad with "00" to multiple of 8 bytes (EMV book 2 annex 1.2.1)
		string combined = ARQC + data + "80";
		string ARPC = GenerateAC(key, combined, "00");

		// method 2 uses a 4 byte MAC, so only return the first 8 hex digits
		printf("ARPC is %s\n", ARPC.substr(0, 8).c_str());
		return 0;
	}


	if(udk)
	{
		if(PAN == "")
		{
			printf("No PAN specified!\n");
			return -1;
		}
		if(seq == "")
		{
			printf("Provide sequence number.\n");
			return -1;
		}

		string UDK = GenerateUDK(key, PAN, seq);
		printf("UDK is %s\n", UDK.c_str());
		return 0;
	}

	padData(data);

	if(useRSA)
	{
		if(data == "")
		{
			printf("No data specified!  Provide hexidecimal string with data.\n");
			return -1;
		}

		string output = "";
		try
		{
			RSAKey rsa;
			if(encrypt)
			{
				output = rsa.EncryptRSA(data, key);
			}
			else
			{
				output = rsa.DecryptRSA(data, key, kek, useECB);
			}
		}
		catch(const char *e)
		{
			printf("Exception:  %s\n", e);
		}

		printf("Output: %s\n", output.c_str());

		return 0;
	}

	// hex2bin will throw an exception for invalid hex strings, so catch
	//  and handle those with a reasonable error message
	try
	{
		if(findKCV)
		{
			char input[] = "0000000000000000";
			char output[64];
			int parity = 0;

			if(kek != "")
			{
				printf("Decrypting DES key with KEK\n");

				// decrypt data with KEK first
				char plaintextKey[64];
				DecryptDES(key.c_str(), kek.c_str(), true, plaintextKey);

				if(checkParity) 
				{
					bool odd = CheckParity(plaintextKey);
					printf("Parity is %s\n", odd ? "odd" : "even");
				}
				// then encrypt string of zeros with decrypted key	
				EncryptDES(input, plaintextKey, true, output);
			}
			else
			{
				if(checkParity) 
				{
					bool odd = CheckParity(key.c_str());
					printf("Parity is %s\n", odd ? "odd" : "even");
				}

				// encrypt string of zeros with key
				EncryptDES(input, key.c_str(), true, output);
			}

			// clip at 6 characters
			output[6] = 0;

			printf("KCV is %s\n", output);

			return 0;
		}
		
		if(PIN != "")
		{
			if(PAN.length() != 16)
				throw (const char *)"PIN operations require the 16 digit PAN.";

			if(encrypt)
			{
				if(PIN.length() != 4)
					throw (const char *)"Encrypting PIN requires 4 digit PIN.";

				string block1;
				string block2;

				block1 = "04" + PIN + "FFFFFFFFFF";	
				block2 = "0000" + PAN.substr(3, 12);

				unsigned char result[8];
				for(int i = 0; i < 8; ++i)
					result[i] = ByteFromStr((char *)&block1.c_str()[i * 2]) ^ 
						ByteFromStr((char *)&block2.c_str()[i * 2]); 

				char combined[32];
				bin2hex(result, 8, combined);
				char encrypted[4096];
				EncryptDES(combined, key.c_str(), true, encrypted);

				printf("Block 1:  %s block 2: %s ", block1.c_str(), block2.c_str());
				printf("decrypted: %s  encrypted PIN block: %s\n", combined, encrypted);
			}
			else
			{
				if(PIN.length() != 16)
				{
					printf("PIN <%s> %i\n", PIN.c_str(), PIN.length());
					throw (const char *)"Decrypting PIN requires 16 character PIN block.";
				}

				char block1[64];
				char block2[64];
				sprintf(block2, "0000%s", PAN.substr(3, 12).c_str());

				DecryptDES(PIN.c_str(), key.c_str(), true, block1);

				printf("Decrypted: %s block 2: %s ", block1, block2);
				
				unsigned char result[8];
				printf("block 1: ");
				for(int i = 0; i < 8; ++i)
				{
					result[i] = ByteFromStr((char *)&block1[i * 2]) ^ 
						ByteFromStr((char *)&block2[i * 2]); 
					printf("%02x", result[i]);
				}
				printf(" extracted PIN: %02x%02x\n", result[1], result[2]);
			}
			return 0;
		}

		char output[4096] = {0};
		if(encrypt)
		{
			EncryptDES(data.c_str(), key.c_str(), useECB, output);
			printf("Encrypted data:  %s\n", output);
		}
		else if(decrypt)
		{
			DecryptDES(data.c_str(), key.c_str(), useECB, output);
			printf("Decrypted data:  %s\n", output);
		}
	}
	catch(char c)
	{
		printf("Fatal error:  Invalid character \"%c\" found in hexidecimal string\n", c);
		return -1;
	}
	catch(const char *msg)
	{
		printf("Fatal error:  %s\n", msg);
		return -1;
	}
	catch(...)
	{
		printf("Caught unknown exception type\n");
		return -1;
	}

	if(checkParity)
	{
		bool odd = CheckParity(key.c_str());
		if(odd)
			printf("Key is odd parity.\n");	
		else
			printf("Key is even parity.\n");	
	}

	if(export3components)
	{
		// generate random values the same length as the key
		string random1 = GenerateRandom(key.length());
		string random2 = GenerateRandom(key.length());
		
		// 1 string to hold the third component, which is the key XORed with random numbers
		string composite;
		// combine key and first random value with XOR
		composite = StringXOR(key, random1);

		// XOR in second value
		composite = StringXOR(composite, random2);

		printf("Three components:\n\n%s\n%s\n%s\n\n", random1.c_str(), random2.c_str(), composite.c_str());
		return 0;
	}

	return 0;
}

