#ifndef main_h_included
#define main_h_included

void padData(string &data, string pad = "BB");
bool DecryptDES(const char *input, const char *key, bool useECB, char *output);
bool EncryptDES(const char *input, const char *key, bool useECB, char *output);

#endif
