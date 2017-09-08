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
		in >> str >> str >> str;//����������Ϣ��ͷ��Ϣ��ͷ��Ϣ
		string *decoded_str = new string;
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
		string *decoded_str = new string;
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

void initPeople(Person& alice,Person& bob, CA& ca)
{
	int ca_method = getCAMethod();
	cout << "Alice��������RSA��Կ��" << endl;
	alice.rsa.generateKeyPair();
	cout << "������Alice������:";
	alice.setID();
	alice.setCert(ca.requare(alice.getID(), alice.rsa.getPK(), ca_method));
	ca.createCertFile(alice.getID(), alice.getCert());
	cout << "Bob��������RSA��Կ��" << endl;
	bob.rsa.generateKeyPair();
	cout << "������Bob������:";
	bob.setID();
	bob.setCert(ca.requare(bob.getID(), bob.rsa.getPK(), ca_method));
	ca.createCertFile(bob.getID(), bob.getCert());
}

int main()
{
	if (0)
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
		RSA::PublicKey *pk = rsa_signature.getPK();//bob��ù�Կ
		cout << "��֤���Ϊ������Ϊ1)��" << RSA::RsaSignature::ver(x, y, pk) << endl;
		cout << "�����ǩ����֤���Ϊ������Ϊ0)��"
			<< RSA::RsaSignature::ver(x, y + 1, pk) << endl;
		cout << endl;
	}
	if (false)
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
		ElGamal::PublicKey *pk = el_gamal_signature.getPK();//bob��ù�Կ
		cout << "��֤���Ϊ������Ϊ1)��" << ElGamal::ElGamalSignature::ver(x, y, pk) << endl;
		cout << "�����ǩ����֤���Ϊ������Ϊ0)��"
			<< ElGamal::ElGamalSignature::ver(x, y + 1, pk) << endl;
		cout << endl;
	}
	// ��3����Գ���
	if (0)
	{
		Person alice;
		CA ca;
		cout << "Alice��������RSA��Կ��" << endl;
		alice.rsa.generateKeyPair();
		cout << "������Alice������:";
		alice.setID();
		int ca_method = getCAMethod();
		string alice_cert = ca.requare(alice.getID(), alice.rsa.getPK(), ca_method);
		alice.setCert(alice_cert);
	}
	// ��4����Գ���
	if (0)
	{
		Person alice;
		Person bob;
		CA ca;


		ZZ bob_random_challenge = RandomBits_ZZ(4096);//bobѡ��һ�������ս
		ZZ alice_random_challenge = RandomBits_ZZ(4096);//aliceѡ��һ�������ս
		ZZ y1 = alice.rsa.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		RSA::PublicKey *alices_pk = bob.openRsaCert(file);//Alice��bob��֤�飡��������
		cout << "��֤���Ϊ������Ϊ1)��" <<
			RSA::RsaSignature::ver(Cryptography::stringToNumber(
				bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.rsa.sig(alice.getID() + alice_random_challenge);
		RSA::PublicKey *bob_pk = alice.openRsaCert(bob.getID() + ".txt");// bob��alice��֤�飡
		cout << "��֤���Ϊ������Ϊ1)��" <<
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


		ZZ bob_random_challenge = RandomBits_ZZ(4096);//bobѡ��һ�������ս
		ZZ alice_random_challenge = RandomBits_ZZ(4096);//aliceѡ��һ�������ս
		ZZ y1 = alice.el_gamal.sig(bob.getID() + bob_random_challenge + alice_random_challenge);

		string file = alice.getID() + ".txt";
		ElGamal::PublicKey *alices_pk = bob.openElGamalCert(file);//Alice��bob��֤�飡��������
		cout << "��֤���Ϊ������Ϊ1)��" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				bob.getID() + bob_random_challenge + alice_random_challenge), y1, alices_pk)
			<< endl;

		ZZ y2 = bob.el_gamal.sig(alice.getID() + alice_random_challenge);
		ElGamal::PublicKey *bob_pk = alice.openElGamalCert(bob.getID() + ".txt");// bob��alice��֤�飡
		cout << "��֤���Ϊ������Ϊ1)��" <<
			ElGamal::ElGamalSignature::ver(Cryptography::stringToNumber(
				alice.getID() + alice_random_challenge), y2, bob_pk)
			<< endl;
	}
	//���������
	if (true)
	{
		Person U, V;
		CA ca;
		ElGamal::ElGamalSignature key;
		key.generateKeyPair(1024);
		ElGamal::PublicKey* k=key.getPK();
		ZZ p = k->p;
		ZZ alpha = k->alpha;

		int au = RandomBnd(1023)+1;// U������ָ��au
		ZZ bu = PowerMod(alpha, au, p);
		ca.createCertFile("U", ca.requareMTI("U", bu, 1));
		int ru = RandomBnd(1023)+1;// U���ѡȡru
		ZZ su = PowerMod(alpha, ru, p);
		// U��cert��su���͸�V
		int av = RandomBnd(1023) + 1;
		ZZ bv = PowerMod(alpha, av, p);
		ca.createCertFile("V", ca.requareMTI("V", bu, 1));
		int rv = RandomBnd(1023)+1;
		ZZ sv = PowerMod(alpha, rv, p);
		// V��cert��su���͸�U

		// v����Ự��Կ
		ZZ vk = PowerMod(su, av, p)*PowerMod(bu, rv, p) % p;
		cout << "V����õ��Ự��Կ��"<<vk << endl;
		ZZ uk = PowerMod(sv, au, p)*PowerMod(bv, ru, p) % p;
		cout << "U����õ��Ự��Կ��"<<uk << endl;
	}
}
