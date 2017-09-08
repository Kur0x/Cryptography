#include <NTL/ZZ.h>
#include "../MMX/ElGamalSignature.h"
#include "../MMX/ElGamalSignature.cpp"
using namespace std;
using namespace NTL;

int main()
{
	if (true)
	{
		ElGamal::ElGamalSignature el_gamal_signature;
		cout << "正在生成秘钥。。。" << endl;
		el_gamal_signature.generateKeyPair(1024);
		cout << "秘钥生成完毕" << endl;
		cout << "p是:" << el_gamal_signature.getPK()->p << endl << endl;
		cout << "alpha是:" << el_gamal_signature.getPK()->alpha << endl << endl;
		cout << "beta是:" << el_gamal_signature.getPK()->beta << endl << endl;
		cout << "a是:" << el_gamal_signature.getSK()->a << endl << endl;
		ZZ x;
		cout << "Alice测试" << endl;
		cout << "请输入要签名的数字:" << endl;
		cin >> x;
		ZZ y = el_gamal_signature.sig(x);
		cout << "签名为：" << y << endl << endl;
		cout << "Bob测试" << endl;
		cout << "Bob获得信息x为：" << x << endl << endl;
		cout << "Bob获得签名y为：" << y << endl << endl;
		ElGamal::PublicKey *pk = el_gamal_signature.getPK();//bob获得公钥
		cout << "验证结果为（理论为1)：" << ElGamal::ElGamalSignature::ver(x, y, pk) << endl;
		cout << "错误的签名验证结果为（理论为0)："
			<< ElGamal::ElGamalSignature::ver(x, y + 1, pk) << endl;
		cout << endl;
	}

}