#include "Cryptography.h"
//#include <sstream>

ZZ Cryptography::stringToNumber(string str, bool bin)
{
	// 二进制模式。可以把字母转换成数字
	if (bin)
	{
		ZZ number = conv<ZZ>(str[0]);
		long len = str.length();
		for (long i = 1; i < len; i++)
		{
			number *= 128;
			number += conv<ZZ>(str[i]);
		}
		return number;
	}
	// 数字模式。字符串中就是数字才能用这个！仅当字符串为”123”这样的数字串时才可以使用
		return conv<ZZ>(str.c_str());
}

string Cryptography::numberToString(ZZ num, bool bin)
{
	if (bin)
	{
		long len = ceil(log(num) / log(128));
		string str;
		str.resize(len);
		for (long i = len - 1; i >= 0; i--)
		{
			str[i] = conv<int>(num % 128);
			num /= 128;
		}
		return str;
	}
	string s="";
//	stringstream ss;
//	ss << num;
//	ss >> s;
	while (num!=0)
	{
		s.insert(s.begin(), char(num % 10 + '0'));
		num /= 10;
	}

	return s;

}
