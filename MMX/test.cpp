#include "RsaSignature.h"
#include "ElGamalSignature.h"
#include "Cryptography.h"
#include "CA.h"
#include <fstream>
#include "Base64.h"
#include <sstream>

class Person
{
public:
	RSA::RsaSignature rsa;
	ElGamal::ElGamalSignature el_gamal;

	string getID() const
	{
		return id;
	}

	void setID()
	{
		cin >> id;
	}

	string getCert() const
	{
		return cert;
	}

	void setCert(const string& cert)
	{
		this->cert = cert;
	}

	RSA::PublicKey* openRsaCert(const string& file)
	{
		fstream in(file, ios::in);
		if (!in.is_open())
			throw false;
		string str;
		in >> str >> str >> str;//读掉无用信息：头信息，头信息
		string* decoded_str = new string;
		Base64::Decode(str, decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string n, b;
		sin >> name >> n >> b;//读掉无用信息名字
		RSA::PublicKey* pk = new RSA::PublicKey(
			Cryptography::stringToNumber(n, false), Cryptography::stringToNumber(b, false));
		in.close();
		return pk;
	}

	ElGamal::PublicKey* openElGamalCert(const string& file)
	{
		fstream in(file, ios::in);
		if (!in.is_open())
			throw false;
		string str;
		in >> str >> str >> str;//读掉无用信息：头信息，头信息
		string* decoded_str = new string;
		Base64::Decode(str, decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string p, alpha, beta;
		sin >> name >> p >> alpha >> beta;//读掉无用信息名字
		ElGamal::PublicKey* pk = new ElGamal::PublicKey(
			Cryptography::stringToNumber(p, false),
			Cryptography::stringToNumber(alpha, false),
			Cryptography::stringToNumber(beta, false));
		in.close();
		return pk;
	}

private:
	string id;
	string cert;
};

string operator+(const ZZ& zz, const string& cs)//辅助函数，增加函数可读性！
{
	return cs + ' ' + Cryptography::numberToString(zz);
}

string operator+(const string& cs, const ZZ& zz)//辅助函数，增加函数可读性！
{
	return cs + ' ' + Cryptography::numberToString(zz);
}

int getCAMethod()
{
	cout << "请输入CA的签名方式，1表示RSA，2表示ElGamal";
	int method;
	cin >> method;
	return method;
}

int initPeople(Person& alice, Person& bob, CA& ca)
{
	cout << "请输入CA的签名方式，1表示RSA，2表示ElGamal：";
	int ca_sig_method, user_sig_method;
	cin >> ca_sig_method;
	cout << "请输入用户的签名方式，1表示RSA，2表示ElGamal：";
	cin >> user_sig_method;
	if (user_sig_method == 1)
	{
		cout << "Alice正在生成RSA秘钥对" << endl;
		alice.rsa.generateKeyPair();
	}
	else
	{
		cout << "Alice正在生成ElGamal秘钥对" << endl;
		alice.el_gamal.generateKeyPair();
	}
	cout << "请输入Alice的姓名:";
	alice.setID();
	if (user_sig_method == 1)
		alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_sig_method));
	else
		alice.setCert(ca.requare(alice.getID(), alice.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(alice.getID(), alice.getCert());// 创建证书文件
	if (user_sig_method == 1)
	{
		cout << "Bob正在生成RSA秘钥对" << endl;
		bob.rsa.generateKeyPair();
	}
	else
	{
		cout << "Bob正在生成ElGamal秘钥对" << endl;
		bob.el_gamal.generateKeyPair();
	}
	cout << "请输入Bob的姓名:";
	bob.setID();
	if (user_sig_method == 1)
		bob.setCert(ca.requare(bob.getID(), bob.rsa.getPK(), ca_sig_method));
	else
		bob.setCert(ca.requare(bob.getID(), bob.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(bob.getID(), bob.getCert());// 创建证书文件
	return user_sig_method;
}

int chooseMethod()
{
	cout << "请输入要使用的方法，1：RSA,2:ElGamal" << endl;
	int i;
	cin >> i;
	return i;
}

//	7．1节的RSA签名方案
void test1()
{
	RSA::RsaSignature rsa_signature;
	cout << "正在生成秘钥。。。" << endl;
	rsa_signature.generateKeyPair();
	cout << "秘钥生成完毕" << endl;
	cout << "p是:" << rsa_signature.getSK()->p << endl << endl;
	cout << "q是:" << rsa_signature.getSK()->q << endl << endl;
	cout << "n是:" << rsa_signature.getSK()->n << endl << endl;
	cout << "a是:" << rsa_signature.getSK()->a << endl << endl;
	cout << "b是:" << rsa_signature.getPK()->b << endl << endl;
	ZZ x;
	cout << "Alice测试" << endl;
	cout << "请输入要签名的数字:" << endl;
	cin >> x;
	ZZ y = rsa_signature.sig(x);
	cout << "签名为：" << y << endl << endl;
	cout << "Bob测试" << endl;
	cout << "Bob获得信息x为：" << x << endl << endl;
	cout << "Bob获得签名y为：" << y << endl << endl;
	RSA::PublicKey* pk = rsa_signature.getPK();//bob获得公钥
	cout << "验证结果为（理论为1)：" << RSA::RsaSignature::ver(x, y, pk) << endl;
	cout << "测试错误的签名验证结果为（理论为0)："
		<< RSA::RsaSignature::ver(x, y + 1, pk) << endl;
	cout << endl;
}

//	7．3节的ElGamal签名方案
void test2()
{
	ElGamal::ElGamalSignature el_gamal_signature;
	cout << "正在生成秘钥。。。" << endl;
	el_gamal_signature.generateKeyPair();
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
	ElGamal::PublicKey* pk = el_gamal_signature.getPK();//bob获得公钥
	cout << "验证结果为（理论为1)：" << ElGamal::ElGamalSignature::ver(x, y, pk) << endl;
	cout << "错误的签名验证结果为（理论为0)："
		<< ElGamal::ElGamalSignature::ver(x, y + 1, pk) << endl;
	cout << endl;
}

// 第3题测试程序
void test3()
{
	Person alice;
	Person bob;
	CA ca;
	// 证书颁发
	cout << "请输入CA的签名方式，1表示RSA，2表示ElGamal:";
	int ca_sig_method, user_sig_method;
	cin >> ca_sig_method;
	cout << "请输入用户的签名方式，1表示RSA，2表示ElGamal:" ;
	cin >> user_sig_method;
	if (user_sig_method == 1)
	{
		cout << "Alice正在生成RSA秘钥对" << endl;
		alice.rsa.generateKeyPair();
	}
	else
	{
		cout << "Alice正在生成ElGamal秘钥对" << endl;
		alice.el_gamal.generateKeyPair();
	}
	cout << "请输入Alice的姓名:";
	alice.setID();
	if (user_sig_method == 1)
		alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_sig_method));
	else
		alice.setCert(ca.requare(alice.getID(), alice.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(alice.getID(), alice.getCert());// 创建证书文件
	// 证书验证
	if (user_sig_method == 1)
	{
		string* decoded_str = new string;
		Base64::Decode(alice.getCert(), decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string n, b, s;
		sin >> name >> n >> b >> ca_sig_method >> s;

		int ver;
		if (ca_sig_method == 1)
			ver = RSA::RsaSignature::ver(Cryptography::stringToNumber(name + ' ' + n + ' ' + b), Cryptography::stringToNumber(s, false), ca.getRSAPK());
		else
			ver = ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(name + ' ' + n + ' ' + b), Cryptography::stringToNumber(s, false), ca.getElGamalPK());
		cout << "证书验证结果为(理论为1)：" << ver << endl;
	}
	else
	{
		string* decoded_str = new string;
		Base64::Decode(alice.getCert(), decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string p, alpha, beta, s;
		sin >> name >> p >> alpha >> beta >> ca_sig_method >> s;
		int ver;
		if (ca_sig_method == 1)
			ver = RSA::RsaSignature::ver(Cryptography::stringToNumber(name + ' ' + p + ' ' + alpha + ' ' + beta), Cryptography::stringToNumber(s, false), ca.getRSAPK());
		else
			ver = ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(name + ' ' + p + ' ' + alpha + ' ' + beta), Cryptography::stringToNumber(s, false), ca.getElGamalPK());
		cout << "证书验证结果为(理论为1)：" << ver << endl;
	}
}

// 第4题测试程序
void test4()
{
	Person alice;
	Person bob;
	CA ca;
	int user_sig_method = initPeople(alice, bob, ca);
	ZZ bob_random_challenge = RandomBits_ZZ(4096);//bob选了一个随机挑战
	ZZ alice_random_challenge = RandomBits_ZZ(4096);//alice选了一个随机挑战

	if (user_sig_method == 1)
	{
		ZZ y1 = alice.rsa.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string alices_file = alice.getID() + ".txt";
		RSA::PublicKey* alices_pk = bob.openRsaCert(alices_file);//bob打开alice的证书！！！！！
		cout << "验证结果为（理论为1)：" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				                       bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.rsa.sig(alice.getID() + alice_random_challenge);
		RSA::PublicKey* bob_pk = alice.openRsaCert(bob.getID() + ".txt");// alice打开bob的证书！
		cout << "验证结果为（理论为1)：" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				                       alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
	else
	{
		ZZ y1 = alice.el_gamal.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		ElGamal::PublicKey* alices_pk = bob.openElGamalCert(file);//bob打开alice的证书！！！！！
		cout << "验证结果为（理论为1)：" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				                               bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.el_gamal.sig(alice.getID() + alice_random_challenge);
		ElGamal::PublicKey* bob_pk = alice.openElGamalCert(bob.getID() + ".txt");// bob打开alice的证书！
		cout << "验证结果为（理论为1)：" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				                               alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
}

//第5题测试
void test5()
{
	Person U, V;
	CA ca;// 用于创建证书文件
	ElGamal::ElGamalSignature key;
	cout << "正在生成1024位ElGamal秘钥..." << endl;
	key.generateKeyPair(1024);
	ElGamal::PublicKey* k = key.getPK();
	ZZ p = k->p;
	ZZ alpha = k->alpha;

	int au = RandomBnd(1023) + 1;// U的秘密指数au
	ZZ bu = PowerMod(alpha, au, p);
	ca.createCertFile("U", ca.requareMTI("U", bu, 1));
	int ru = RandomBnd(1023) + 1;// U随机选取ru
	ZZ su = PowerMod(alpha, ru, p);
	// U将cert和su发送给V
	int av = RandomBnd(1023) + 1;
	ZZ bv = PowerMod(alpha, av, p);
	ca.createCertFile("V", ca.requareMTI("V", bu, 1));
	int rv = RandomBnd(1023) + 1;
	ZZ sv = PowerMod(alpha, rv, p);
	// V将cert和su发送给U

	// v计算会话公钥
	ZZ vk = PowerMod(su, av, p) * PowerMod(bu, rv, p) % p;
	cout << "V计算得到会话密钥：" << vk << endl;
	ZZ uk = PowerMod(sv, au, p) * PowerMod(bv, ru, p) % p;
	cout << "U计算得到会话密钥：" << uk << endl;
	cout << "验证是否相同（理论为1)：" << (vk == uk) << endl;
}

int main()
{
	cout << "欢迎使用密码学工具测试" << endl;
	cout << "请输入您要使用的功能" << endl;
	cout << "1. 单项测试" << endl;
	cout << "2. 完整测试" << endl;
	int i;
	cin >> i;
	if(i==1)
	{
		cout << "请输入测试编号" << endl;
		cout << "1. 测试《密码学原理与实践》 7．1节的RSA签名方案" << endl;
		cout << "2. 测试《密码学原理与实践》 7．3节的ElGamal签名方案" << endl;
		cout << "3. 测试《密码学原理与实践》 9．3．1节的基本证书方案" << endl;
		cout << "4. 测试《密码学原理与实践》 9·3·2 节的协议9．6 公钥环境下的交互认证" << endl;
		cout << "5. 测试《密码学原理与实践》 11.3节的协议11.3" << endl;
		cin >> i;
		switch (i)
		{
			case 1:test1();break;
			case 2:test2();break;
			case 3:test3();break;
			case 4:test4();break;
			case 5:test5();break;
			default:break;
		}
		system("pause");
		return 0;
	}
	// 完整测试
	cout << "1. 测试《密码学原理与实践》 7．1节的RSA签名方案" << endl;
	test1();
	system("pause");
	cout << "2. 测试《密码学原理与实践》 7．3节的ElGamal签名方案" << endl;
	test2();
	system("pause");
	cout << "3. 测试《密码学原理与实践》 9．3．1节的基本证书方案" << endl;
	test3();
	system("pause");
	cout << "4. 测试《密码学原理与实践》 9·3·2 节的协议9．6 公钥环境下的交互认证" << endl;
	test4();
	system("pause");
	cout << "5. 测试《密码学原理与实践》 11.3节的协议11.3" << endl;
	test5();
	system("pause");
	return 0;
}