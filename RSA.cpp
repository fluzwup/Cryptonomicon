#include "RSA.h"
#include "DES.h"
#include "main.h"
#include "Flint/flintpp.h"

// clean up whitespace, check for non-hex digits, make uppercase
string cleanHEX(string buffer)
{
	string output = "";
	int len = buffer.length();
	for(int i = 0; i < len; ++i)
	{
		if(buffer[i] >= '0' && buffer[i] <= '9')
			output += buffer[i];
		else if(buffer[i] >= 'A' && buffer[i] <= 'F')
			output += buffer[i];
		else if(buffer[i] >= 'a' && buffer[i] <= 'f')
			output += (buffer[i] - ('a' - 'A'));
		else if(buffer[i] == ' ' || buffer[i] == '\n' || buffer[i] == '\t')
			; // just ignore whitespace
		else
			throw "Invalid character in hex string.";
	}
	return output;
}

string ReadComponent(FILE *fp)
{
	if(feof(fp)) return "";

	char buffer[32767];
	buffer[0] = 0;
	fgets(buffer, 32767, fp);

	return cleanHEX(buffer);
}

bool RSAKey::ReadKeyFile(string keyFile, string kek, bool useECB)
{
	n = e = d = p = q = dP = dQ = qInv = "";

	FILE *fp = fopen(keyFile.c_str(), "rt");
	if(fp == NULL) throw "RSA key file must exist.";

	n = ReadComponent(fp);
	e = ReadComponent(fp);
	d = ReadComponent(fp);
	p = ReadComponent(fp);
	q = ReadComponent(fp);
	dP = ReadComponent(fp);
	dQ = ReadComponent(fp);
	qInv = ReadComponent(fp);

	if(kek != "")
	{
		char buffer[32768];

		if(d != "")
		{
			DecryptDES(d.c_str(), kek.c_str(), useECB, buffer);
			d = buffer;
		}
		if(p != "")
		{
			DecryptDES(p.c_str(), kek.c_str(), useECB, buffer);
			p = buffer;
		}
		if(q != "")
		{
			DecryptDES(q.c_str(), kek.c_str(), useECB, buffer);
			q = buffer;
		}
		if(dP != "")
		{
			DecryptDES(dP.c_str(), kek.c_str(), useECB, buffer);
			dP = buffer;
		}
		if(dQ != "")
		{
			DecryptDES(dQ.c_str(), kek.c_str(), useECB, buffer);
			dQ = buffer;
		}
		if(qInv != "")
		{
			DecryptDES(qInv.c_str(), kek.c_str(), useECB, buffer);
			qInv = buffer;
		}
	}

	if(n == "") throw "RSA key file must contain a modulus.";
	if(e == "") throw "RSA key file must contain a public exponent.";

	keyLen = n.length();
	if(keyLen % 2) throw "RSA key modulus must be an even number of hex digits.";

	if(d != "" && d.length() != keyLen) throw "Private exponent length must match modulus length.";

	if(p != "" && p.length() != keyLen / 2) throw "CRT component lengths must be half the modulus length.";
	if(q != "" && q.length() != keyLen / 2) throw "CRT component lengths must be half the modulus length.";
	if(dP != "" && dP.length() != keyLen / 2) throw "CRT component lengths must be half the modulus length.";
	if(dQ != "" && dQ.length() != keyLen / 2) throw "CRT component lengths must be half the modulus length.";
	if(qInv != "" && qInv.length() != keyLen / 2) throw "CRT component lengths must be half the modulus length.";
	
	return true;
}

string RSAKey::EncryptRSA(string input, string keyFile)
{
	if(keyFile != "") ReadKeyFile(keyFile);
	if(n == "" || e == "") throw "Cannot perform RSA encryption without public key components.";

	string msg = cleanHEX(input);

	LINT M(msg.c_str(), 16);
	unsigned short E = strtoul(e.c_str(), NULL, 16);
	LINT N(n.c_str(), 16);

	LINT c = mexpkm(M, E, N);

	return cleanHEX(c.hexstr());
}

string RSAKey::DecryptRSA(string input, string keyFile, string kek, bool useECB)
{
	if(keyFile != "") ReadKeyFile(keyFile, kek, useECB);

	// make sure we have modulus
	if(n == "") throw "Cannot perform RSA decryption without a modulus.";
	// and private exponent or CRT components
	if((d == "") && (p == "" || q == "" || dP == "" || dQ == "" || qInv == "")) 
		throw "Cannot perform RSA decryption without a private exponent or CRT components.";

	string cipher = cleanHEX(input);
	LINT C(cipher.c_str(), 16);

	if(d != "")
	{
		LINT N(n.c_str(), 16);
		LINT D(d.c_str(), 16);
	
		// m = c^d mod n
		LINT M = mexpkm(C, D, N);

		return cleanHEX(M.hexstr());
	}

	// make sure we have all five
	if(p == "" || q == "" || dP == "" || dQ == "" || qInv == "")
		throw "All five CRT components are needed.";

	LINT N(n.c_str(), 16);
	LINT P(p.c_str(), 16);
	LINT Q(q.c_str(), 16);
	LINT DP(dP.c_str(), 16);
	LINT DQ(dQ.c_str(), 16);
	LINT QInv(qInv.c_str(), 16);

	// m1 = c^dP mod p
	// m2 = c^dQ mod q
	// h = qInv*(p + m1 - m2) mod p  (Add an extra p to keep things positive.)
	// m = m2 + h*q

	LINT M1 = mexpkm(C, DP, P);
	LINT M2 = mexpkm(C, DQ, Q);
	LINT H = QInv.mmul(P + M1 - M2, P);
	LINT M = M2 + H * Q;

	return cleanHEX(M.hexstr());
}

bool RSAKey::ValidateRSAKey(string keyFile, string kek, bool useECB)
{
	// random quote from Snow Crash to encrypt/decrypt
	const char text[] = "CHISELED SPAM is what you will see in the mirror if you surf on a weak "
		"plank with dumb, fixed wheels and interface with a muffler, retread, snow turd, road "
		"kill, driveshaft, railroad tie, or unconscious pedestrian.  If you think this is "
		"unlikely, you've been surfing too many ghost malls. All of these obstacles and more "
		"were recently observed on a one-mile stretch of the New Jersey Turnpike. Any surfer "
		"who tried to groove that 'vard on a stock plank would have been sneezing brains.  "
		"Don't listen to so-called purists who claim any obstacle can be jumped. Professional "
		"Kouriers know: If you have pooned a vehicle moving fast enough for fun and profit, "
		"your reaction time is cut to tenths of a second-even less if you are way spooled.  "
		"Buy a set of RadiKS Mark II Smartwheels-it's cheaper than a total face retread and a "
		"lot more fun. Smartwheels use sonar, laser rangefinding, and millimeter-wave radar "
		"to identify mufflers and other debris before you even get honed about them.  Don't "
		"get Midasized-upgrade today.";

	ReadKeyFile(keyFile, kek, useECB);
	if(d == "" && p == "") throw "Cannot validate RSA key without private exponent or CRT components.";

	string msg = "";
	// convert the appropriate amount of text into hex digits
	for(int i = 0; i < keyLen / 2; ++i)
	{
		char hex[4];
		sprintf(hex, "%02X", text[i]);
		msg += hex;
	}

	// encrypt message with public key
	string cipher = cleanHEX(EncryptRSA(msg));

	// verify with private exponent, if present
	if(d != "")
	{
		string output = cleanHEX(DecryptRSA(cipher));
		if(output != msg) return false;
	}
	
	// verify with CRT components, if present
	if(p != "")
	{
		string output = cleanHEX(DecryptRSA(cipher));
		if(output != msg) return false;
	}

	return true;
}
