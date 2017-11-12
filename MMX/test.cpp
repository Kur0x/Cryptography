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
		in >> str >> str >> str;//����������Ϣ��ͷ��Ϣ��ͷ��Ϣ
		string* decoded_str = new string;
		Base64::Decode(str, decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string n, b;
		sin >> name >> n >> b;//����������Ϣ����
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
		in >> str >> str >> str;//����������Ϣ��ͷ��Ϣ��ͷ��Ϣ
		string* decoded_str = new string;
		Base64::Decode(str, decoded_str);
		stringstream sin(*decoded_str, ios::in);
		string name;
		string p, alpha, beta;
		sin >> name >> p >> alpha >> beta;//����������Ϣ����
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

string operator+(const ZZ& zz, const string& cs)//�������������Ӻ����ɶ��ԣ�
{
	return cs + ' ' + Cryptography::numberToString(zz);
}

string operator+(const string& cs, const ZZ& zz)//�������������Ӻ����ɶ��ԣ�
{
	return cs + ' ' + Cryptography::numberToString(zz);
}

int getCAMethod()
{
	cout << "������CA��ǩ����ʽ��1��ʾRSA��2��ʾElGamal";
	int method;
	cin >> method;
	return method;
}

int initPeople(Person& alice, Person& bob, CA& ca)
{
	cout << "������CA��ǩ����ʽ��1��ʾRSA��2��ʾElGamal��";
	int ca_sig_method, user_sig_method;
	cin >> ca_sig_method;
	cout << "�������û���ǩ����ʽ��1��ʾRSA��2��ʾElGamal��";
	cin >> user_sig_method;
	if (user_sig_method == 1)
	{
		cout << "Alice��������RSA��Կ��" << endl;
		alice.rsa.generateKeyPair();
	}
	else
	{
		cout << "Alice��������ElGamal��Կ��" << endl;
		alice.el_gamal.generateKeyPair();
	}
	cout << "������Alice������:";
	alice.setID();
	if (user_sig_method == 1)
		alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_sig_method));
	else
		alice.setCert(ca.requare(alice.getID(), alice.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(alice.getID(), alice.getCert());// ����֤���ļ�
	if (user_sig_method == 1)
	{
		cout << "Bob��������RSA��Կ��" << endl;
		bob.rsa.generateKeyPair();
	}
	else
	{
		cout << "Bob��������ElGamal��Կ��" << endl;
		bob.el_gamal.generateKeyPair();
	}
	cout << "������Bob������:";
	bob.setID();
	if (user_sig_method == 1)
		bob.setCert(ca.requare(bob.getID(), bob.rsa.getPK(), ca_sig_method));
	else
		bob.setCert(ca.requare(bob.getID(), bob.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(bob.getID(), bob.getCert());// ����֤���ļ�
	return user_sig_method;
}

int chooseMethod()
{
	cout << "������Ҫʹ�õķ�����1��RSA,2:ElGamal" << endl;
	int i;
	cin >> i;
	return i;
}

//	7��1�ڵ�RSAǩ������
void test1()
{
	RSA::RsaSignature rsa_signature;
	cout << "����������Կ������" << endl;
	rsa_signature.generateKeyPair();
	cout << "��Կ�������" << endl;
	cout << "p��:" << rsa_signature.getSK()->p << endl << endl;
	cout << "q��:" << rsa_signature.getSK()->q << endl << endl;
	cout << "n��:" << rsa_signature.getSK()->n << endl << endl;
	cout << "a��:" << rsa_signature.getSK()->a << endl << endl;
	cout << "b��:" << rsa_signature.getPK()->b << endl << endl;
	ZZ x;
	cout << "Alice����" << endl;
	cout << "������Ҫǩ��������:" << endl;
	cin >> x;
	ZZ y = rsa_signature.sig(x);
	cout << "ǩ��Ϊ��" << y << endl << endl;
	cout << "Bob����" << endl;
	cout << "Bob�����ϢxΪ��" << x << endl << endl;
	cout << "Bob���ǩ��yΪ��" << y << endl << endl;
	RSA::PublicKey* pk = rsa_signature.getPK();//bob��ù�Կ
	cout << "��֤���Ϊ������Ϊ1)��" << RSA::RsaSignature::ver(x, y, pk) << endl;
	cout << "���Դ����ǩ����֤���Ϊ������Ϊ0)��"
		<< RSA::RsaSignature::ver(x, y + 1, pk) << endl;
	cout << endl;
}

//	7��3�ڵ�ElGamalǩ������
void test2()
{
	ElGamal::ElGamalSignature el_gamal_signature;
	cout << "����������Կ������" << endl;
	el_gamal_signature.generateKeyPair();
	cout << "��Կ�������" << endl;
	cout << "p��:" << el_gamal_signature.getPK()->p << endl << endl;
	cout << "alpha��:" << el_gamal_signature.getPK()->alpha << endl << endl;
	cout << "beta��:" << el_gamal_signature.getPK()->beta << endl << endl;
	cout << "a��:" << el_gamal_signature.getSK()->a << endl << endl;
	ZZ x;
	cout << "Alice����" << endl;
	cout << "������Ҫǩ��������:" << endl;
	cin >> x;
	ZZ y = el_gamal_signature.sig(x);
	cout << "ǩ��Ϊ��" << y << endl << endl;
	cout << "Bob����" << endl;
	cout << "Bob�����ϢxΪ��" << x << endl << endl;
	cout << "Bob���ǩ��yΪ��" << y << endl << endl;
	ElGamal::PublicKey* pk = el_gamal_signature.getPK();//bob��ù�Կ
	cout << "��֤���Ϊ������Ϊ1)��" << ElGamal::ElGamalSignature::ver(x, y, pk) << endl;
	cout << "�����ǩ����֤���Ϊ������Ϊ0)��"
		<< ElGamal::ElGamalSignature::ver(x, y + 1, pk) << endl;
	cout << endl;
}

// ��3����Գ���
void test3()
{
	Person alice;
	Person bob;
	CA ca;
	// ֤��䷢
	cout << "������CA��ǩ����ʽ��1��ʾRSA��2��ʾElGamal:";
	int ca_sig_method, user_sig_method;
	cin >> ca_sig_method;
	cout << "�������û���ǩ����ʽ��1��ʾRSA��2��ʾElGamal:" ;
	cin >> user_sig_method;
	if (user_sig_method == 1)
	{
		cout << "Alice��������RSA��Կ��" << endl;
		alice.rsa.generateKeyPair();
	}
	else
	{
		cout << "Alice��������ElGamal��Կ��" << endl;
		alice.el_gamal.generateKeyPair();
	}
	cout << "������Alice������:";
	alice.setID();
	if (user_sig_method == 1)
		alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_sig_method));
	else
		alice.setCert(ca.requare(alice.getID(), alice.el_gamal.getPK(), ca_sig_method));
	ca.createCertFile(alice.getID(), alice.getCert());// ����֤���ļ�
	// ֤����֤
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
		cout << "֤����֤���Ϊ(����Ϊ1)��" << ver << endl;
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
		cout << "֤����֤���Ϊ(����Ϊ1)��" << ver << endl;
	}
}

// ��4����Գ���
void test4()
{
	Person alice;
	Person bob;
	CA ca;
	int user_sig_method = initPeople(alice, bob, ca);
	ZZ bob_random_challenge = RandomBits_ZZ(4096);//bobѡ��һ�������ս
	ZZ alice_random_challenge = RandomBits_ZZ(4096);//aliceѡ��һ�������ս

	if (user_sig_method == 1)
	{
		ZZ y1 = alice.rsa.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string alices_file = alice.getID() + ".txt";
		RSA::PublicKey* alices_pk = bob.openRsaCert(alices_file);//bob��alice��֤�飡��������
		cout << "��֤���Ϊ������Ϊ1)��" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				                       bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.rsa.sig(alice.getID() + alice_random_challenge);
		RSA::PublicKey* bob_pk = alice.openRsaCert(bob.getID() + ".txt");// alice��bob��֤�飡
		cout << "��֤���Ϊ������Ϊ1)��" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				                       alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
	else
	{
		ZZ y1 = alice.el_gamal.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		ElGamal::PublicKey* alices_pk = bob.openElGamalCert(file);//bob��alice��֤�飡��������
		cout << "��֤���Ϊ������Ϊ1)��" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				                               bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.el_gamal.sig(alice.getID() + alice_random_challenge);
		ElGamal::PublicKey* bob_pk = alice.openElGamalCert(bob.getID() + ".txt");// bob��alice��֤�飡
		cout << "��֤���Ϊ������Ϊ1)��" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				                               alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
}

//��5�����
void test5()
{
	Person U, V;
	CA ca;// ���ڴ���֤���ļ�
	ElGamal::ElGamalSignature key;
	cout << "��������1024λElGamal��Կ..." << endl;
	key.generateKeyPair(1024);
	ElGamal::PublicKey* k = key.getPK();
	ZZ p = k->p;
	ZZ alpha = k->alpha;

	int au = RandomBnd(1023) + 1;// U������ָ��au
	ZZ bu = PowerMod(alpha, au, p);
	ca.createCertFile("U", ca.requareMTI("U", bu, 1));
	int ru = RandomBnd(1023) + 1;// U���ѡȡru
	ZZ su = PowerMod(alpha, ru, p);
	// U��cert��su���͸�V
	int av = RandomBnd(1023) + 1;
	ZZ bv = PowerMod(alpha, av, p);
	ca.createCertFile("V", ca.requareMTI("V", bu, 1));
	int rv = RandomBnd(1023) + 1;
	ZZ sv = PowerMod(alpha, rv, p);
	// V��cert��su���͸�U

	// v����Ự��Կ
	ZZ vk = PowerMod(su, av, p) * PowerMod(bu, rv, p) % p;
	cout << "V����õ��Ự��Կ��" << vk << endl;
	ZZ uk = PowerMod(sv, au, p) * PowerMod(bv, ru, p) % p;
	cout << "U����õ��Ự��Կ��" << uk << endl;
	cout << "��֤�Ƿ���ͬ������Ϊ1)��" << (vk == uk) << endl;
}

int main()
{
	cout << "��ӭʹ������ѧ���߲���" << endl;
	cout << "��������Ҫʹ�õĹ���" << endl;
	cout << "1. �������" << endl;
	cout << "2. ��������" << endl;
	int i;
	cin >> i;
	if(i==1)
	{
		cout << "��������Ա��" << endl;
		cout << "1. ���ԡ�����ѧԭ����ʵ���� 7��1�ڵ�RSAǩ������" << endl;
		cout << "2. ���ԡ�����ѧԭ����ʵ���� 7��3�ڵ�ElGamalǩ������" << endl;
		cout << "3. ���ԡ�����ѧԭ����ʵ���� 9��3��1�ڵĻ���֤�鷽��" << endl;
		cout << "4. ���ԡ�����ѧԭ����ʵ���� 9��3��2 �ڵ�Э��9��6 ��Կ�����µĽ�����֤" << endl;
		cout << "5. ���ԡ�����ѧԭ����ʵ���� 11.3�ڵ�Э��11.3" << endl;
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
	// ��������
	cout << "1. ���ԡ�����ѧԭ����ʵ���� 7��1�ڵ�RSAǩ������" << endl;
	test1();
	system("pause");
	cout << "2. ���ԡ�����ѧԭ����ʵ���� 7��3�ڵ�ElGamalǩ������" << endl;
	test2();
	system("pause");
	cout << "3. ���ԡ�����ѧԭ����ʵ���� 9��3��1�ڵĻ���֤�鷽��" << endl;
	test3();
	system("pause");
	cout << "4. ���ԡ�����ѧԭ����ʵ���� 9��3��2 �ڵ�Э��9��6 ��Կ�����µĽ�����֤" << endl;
	test4();
	system("pause");
	cout << "5. ���ԡ�����ѧԭ����ʵ���� 11.3�ڵ�Э��11.3" << endl;
	test5();
	system("pause");
	return 0;
}