#include "ElGamalSignature.h"
#include <ctime>
#include <NTL/BasicThreadPool.h>
using namespace ElGamal;
PublicKey::PublicKey(const ZZ& p, const ZZ& alpha, const ZZ& beta)
	:p(p), alpha(alpha), beta(beta)
{}

PrivateKey::PrivateKey(const ZZ& a):a(a)
{
}

ElGamalSignature::ElGamalSignature():pk(nullptr),sk(nullptr)
{
	SetSeed(conv<ZZ>(static_cast<long>(time(nullptr))));
}

void ElGamalSignature::generateKeyPair(int len)
{
	ZZ p = findPrime(len);
	ZZ alpha = findPrimitiveRoot(p);
	ZZ a = RandomBnd(p - 2) + 1;//[1,p-1]
	ZZ beta = PowerMod(alpha, a, p);
	pk = new PublicKey(p,alpha,beta);
	sk = new PrivateKey(a);
}

ZZ ElGamalSignature::sig(const ZZ& x, PublicKey* pk ,PrivateKey* sk)
{
	ZZ k= RandomBnd(pk->p - 3) + 1;//[1,p-2]
	while (GCD(k, pk->p - 1) != 1)
	{
		k = RandomBnd(pk->p - 3) + 1;
	}
	ZZ gamma = PowerMod(pk->alpha,k, pk->p);
	//delta = (x-a*gamma)*k^(-1) mod (p-1)
	ZZ delta = MulMod(x - sk->a*gamma, InvMod(k, pk->p - 1), pk->p - 1);
	return gamma*pk->p + delta;
}

ZZ ElGamalSignature::sig(const ZZ& x) const
{
	return this->sig(x, pk, sk);
}
ZZ ElGamalSignature::sig(const string& x) const
{
	return this->sig(stringToNumber(x), pk, sk);
}

bool ElGamalSignature::ver(const ZZ& x, const ZZ& y, PublicKey* pk)
{
	ZZ gamma = y/pk->p;
	ZZ delta = y%pk->p;
	//beta^(gamma)*gamma^delta==alpha^x (mod p)
	return (PowerMod(pk->beta, gamma, pk->p)*PowerMod(gamma,delta, pk->p)) % pk->p == PowerMod(pk->alpha, x, pk->p);
}

ElGamalSignature::~ElGamalSignature()
{
	delete pk;
	delete sk;
}

PublicKey* ElGamalSignature::getPK() const
{
	return pk;
}

PrivateKey* ElGamalSignature::getSK() const
{
	return sk;
}

ZZ ElGamalSignature::findPrime(int len)
{
	ZZ q0 = GenGermainPrime_ZZ(len-1);
	// A (Sophie) Germain prime is a prime p such that p' = 2*p+1 is also a prime.
	// Such primes are useful for cryptographic applications...cryptographers
	// sometimes call p' a "strong" or "safe" prime.
	// GenGermainPrime generates a random Germain prime n of length l
	// so that the probability that either n or 2*n+1 is not a prime
	// is bounded by 2^(-err).
		ZZ p = 2 * q0 + 1;
	return p;
//	while (true)
//	{
//		ZZ r = conv<ZZ>("2");
//		std::cout << NumBits(r)<< std::endl;
//		ZZ q0 = GenPrime_ZZ(len-1);
//		ZZ p = r * q0 + 1;
//		std::cout << NumBits(p) << std::endl;
//		if (ProbPrime(p) == 1)
//			return p;
//	}
}

ZZ ElGamalSignature::findPrimitiveRoot(const ZZ& p)
{
	//p-1的两个因子p1,p2
	ZZ p1 = conv<ZZ>("2");
	ZZ p2 = (p - 1) / p1;
		while (true){
			ZZ g = RandomBnd(p - 3) + 2;
			//g是p的本原元当且仅当g对p-1的所有因子都有g^((p-1)/p[i]) (mod p) 不等于 1
			if (PowerMod(g, (p - 1) / p1, p) != 1)
				if (PowerMod(g, (p - 1) / p2, p) != 1)
					return g;
		}
}
