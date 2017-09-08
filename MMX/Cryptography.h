﻿#pragma once
#include <NTL/ZZ.h>
#define RSA_METHOD 1
#define ELGAMAL_METHOD 2
#define RSA_KEYLEN 512
#define ELGAMAL_KEYLEN 1024
using namespace NTL;
using namespace std;

class Cryptography
{
public:
	static ZZ stringToNumber(string str, bool bin=true);
	static string numberToString(ZZ num, bool bin = true);
private:

};