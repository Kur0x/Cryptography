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
		cout << "����������Կ������" << endl;
		el_gamal_signature.generateKeyPair(1024);
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

}