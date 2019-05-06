/* Output must be same length as input, key must be 8, 16, or 24 bits, input data must be padded to 8 byte boundary */
bool encryptECB(unsigned char *key, int keyLength, unsigned char *data, int dataLength, unsigned char *output);
bool decryptECB(unsigned char *key, int keyLength, unsigned char *data, int dataLength, unsigned char *output);
bool encryptCBC(unsigned char *key, int keyLength, unsigned char *data, int dataLength, unsigned char *output);
bool decryptCBC(unsigned char *key, int keyLength, unsigned char *data, int dataLength, unsigned char *output);

