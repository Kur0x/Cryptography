#include "RsaSignature.h"
#include "ElGamalSignature.h"
#include "Cryptography.h"
#include "CA.h"
#include <fstream>
#include "Base64.h"
#include <sstream>
using namespace std;
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

	void setCert(const string & cert)
	{
		this->cert = cert;
	}
	RSA::PublicKey* openRsaCert(const string&file)
	{
		fstream in(file, ios::in);
		if (!in.is_open())
			throw false;
		string str;
		in >> str >> str >> str;//读掉无用信息：头信息，头信息
		string *decoded_str = new string;
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
		string *decoded_str = new string;
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

void initPeople(Person& alice,Person& bob, CA& ca)
{
	int ca_method = getCAMethod();
	cout << "Alice正在生成RSA秘钥对" << endl;
	alice.rsa.generateKeyPair();
	cout << "请输入Alice的姓名:";
	alice.setID();
	alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_method));
	ca.createCertFile(alice.getID(), alice.getCert());
	cout << "Bob正在生成RSA秘钥对" << endl;
	bob.rsa.generateKeyPair();
	cout << "请输入Bob的姓名:";
	bob.setID();
	bob.setCert(ca.requare(bob.getID(), bob.rsa.getPK(), ca_method));
	ca.createCertFile(bob.getID(), bob.getCert());
}

int main()
{
	if (0)
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
		RSA::PublicKey *pk = rsa_signature.getPK();//bob获得公钥
		cout << "验证结果为（理论为1)：" << RSA::RsaSignature::ver(x, y, pk) << endl;
		cout << "错误的签名验证结果为（理论为0)："
			<< RSA::RsaSignature::ver(x, y + 1, pk) << endl;
		cout << endl;
	}
	if (false)
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
		ElGamal::PublicKey *pk = el_gamal_signature.getPK();//bob获得公钥
		cout << "验证结果为（理论为1)：" << ElGamal::ElGamalSignature::ver(x, y, pk) << endl;
		cout << "错误的签名验证结果为（理论为0)："
			<< ElGamal::ElGamalSignature::ver(x, y + 1, pk) << endl;
		cout << endl;
	}
	// 第3题测试程序
	if (0)
	{
		Person alice;
		CA ca;
		cout << "Alice正在生成RSA秘钥对" << endl;
		alice.rsa.generateKeyPair();
		cout << "请输入Alice的姓名:";
		alice.setID();
		int ca_method = getCAMethod();
		string alice_cert = ca.requare(alice.getID(), alice.rsa.getPK(), ca_method);
		alice.setCert(alice_cert);
	}
	// 第4题测试程序
	if (0)
	{
		Person alice;
		Person bob;
		CA ca;


		ZZ bob_random_challenge = RandomBits_ZZ(4096);//bob选了一个随机挑战
		ZZ alice_random_challenge = RandomBits_ZZ(4096);//alice选了一个随机挑战
		ZZ y1 = alice.rsa.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		RSA::PublicKey *alices_pk = bob.openRsaCert(file);//Alice打开bob的证书！！！！！
		cout << "验证结果为（理论为1)：" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.rsa.sig(alice.getID() + alice_random_challenge);
		RSA::PublicKey *bob_pk = alice.openRsaCert(bob.getID() + ".txt");// bob打开alice的证书！
		cout << "验证结果为（理论为1)：" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
	if (0)
	{
		Person alice;
		Person bob;
		CA ca;
		initPeople(alice,  bob,		 ca);


		ZZ bob_random_challenge = RandomBits_ZZ(4096);//bob选了一个随机挑战
		ZZ alice_random_challenge = RandomBits_ZZ(4096);//alice选了一个随机挑战
		ZZ y1 = alice.el_gamal.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		ElGamal::PublicKey *alices_pk = bob.openElGamalCert(file);//Alice打开bob的证书！！！！！
		cout << "验证结果为（理论为1)：" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.el_gamal.sig(alice.getID() + alice_random_challenge);
		ElGamal::PublicKey *bob_pk = alice.openElGamalCert(bob.getID() + ".txt");// bob打开alice的证书！
		cout << "验证结果为（理论为1)：" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
	//第六题测试
	if (true)
	{
		Person U, V;
		CA ca;
		ElGamal::ElGamalSignature key;
		key.generateKeyPair(1024);
		ElGamal::PublicKey* k=key.getPK();
		ZZ p = k->p;
		ZZ alpha = k->alpha;

		int au = RandomBnd(1023)+1;// U的密码指数au
		ZZ bu = PowerMod(alpha, au, p);
		ca.createCertFile("U", ca.requareMTI("U", bu, 1));
		int ru = RandomBnd(1023)+1;// U随机选取ru
		ZZ su = PowerMod(alpha, ru, p);
		// U将cert和su发送给V
		int av = RandomBnd(1023) + 1;
		ZZ bv = PowerMod(alpha, av, p);
		ca.createCertFile("V", ca.requareMTI("V", bu, 1));
		int rv = RandomBnd(1023)+1;
		ZZ sv = PowerMod(alpha, rv, p);
		// V将cert和su发送给U

		// v计算会话公钥
		ZZ vk = PowerMod(su, av, p)*PowerMod(bu, rv, p) % p;
		cout << "V计算得到会话密钥："<<vk << endl;
		ZZ uk = PowerMod(sv, au, p)*PowerMod(bv, ru, p) % p;
		cout << "U计算得到会话密钥："<<uk << endl;
	}
}
