// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdexcept>
#include <stdint.h>
#include <vector>

#include <gmp.h>
#include <gmpxx.h>

typedef mpz_class mpz;
typedef mpq_class mpq;

mpz inline i64_to_mpz(int64_t nValue)
{
    return mpz(i64tostr(nValue));
}

mpq inline i64_to_mpq(int64_t nValue)
{
    return i64_to_mpz(nValue);
}

int64_t inline mpz_to_i64(const mpz &zValue)
{
    static mpz MPZ_MAX_I64( "9223372036854775807");
    static mpz MPZ_MIN_I64("-9223372036854775808");
    if (zValue < MPZ_MIN_I64 || zValue > MPZ_MAX_I64)
        throw std::runtime_error("mpz_to_i64 : input exceeds range of int64_t type");
    int64_t result = 0;
    mpz tmp(zValue);
    bool sign = tmp < 0;
    if ( sign ) tmp = -tmp;
    result = atoi64(tmp.get_str());
    return (sign ? -result : result);
}

enum
{
    ROUND_TIES_TO_EVEN,
    ROUND_TOWARDS_ZERO,
    ROUND_AWAY_FROM_ZERO,
    ROUND_TOWARD_POSITIVE,
    ROUND_TOWARD_NEGATIVE,
    ROUND_SIGNAL,
};

mpq RoundAbsolute(const mpq &q, int mode=ROUND_TIES_TO_EVEN, int magnitude=0);

inline unsigned int GetSerializeSize(const mpz& a, int nType, int nVersion)
{
    size_t len = (mpz_sizeinbase(a.get_mpz_t(),2) + 7) / 8;
    return VARINT(len).GetSerializeSize(nType, nVersion) + len;
}
template<typename Stream>
inline void Serialize(Stream& s, const mpz& a, int nType, int nVersion)
{
    size_t len = (mpz_sizeinbase(a.get_mpz_t(),2) + 7) / 8;
    VARINT(len).Serialize(s, nType, nVersion);
    unsigned char* buf = static_cast<unsigned char*>(alloca(len));

    mpz_export(buf, 0, -1, 1, -1, 0, a.get_mpz_t());

    for (size_t i = 0; i < len; ++i)
        ::Serialize(s, buf[i], nType, nVersion);
}
template<typename Stream>
inline void Unserialize(Stream& s, mpz& a, int nType, int nVersion)
{
    size_t len = 0;
    VARINT(len).Unserialize(s, nType, nVersion);
    unsigned char* buf = static_cast<unsigned char*>(alloca(len));

    for (size_t i = 0; i < len; ++i)
        ::Unserialize(s, buf[i], nType, nVersion);

    mpz_import(a.get_mpz_t(), len, -1, 1, -1, 0, buf);
}

inline unsigned int GetSerializeSize(const mpq& a, int nType, int nVersion)
{
    mpq q(a);
    q.canonicalize();
    return GetSerializeSize(q.get_num(), nType, nVersion) +
           GetSerializeSize(q.get_den(), nType, nVersion);
}
template<typename Stream>
inline void Serialize(Stream& s, const mpq& a, int nType, int nVersion)
{
    mpq q(a);
    q.canonicalize();
    Serialize(s, q.get_num(), nType, nVersion);
    Serialize(s, q.get_den(), nType, nVersion);
}
template<typename Stream>
inline void Unserialize(Stream& s, mpq& a, int nType, int nVersion)
{
    mpq r;
    Unserialize(s, r.get_num(), nType, nVersion);
    Unserialize(s, r.get_den(), nType, nVersion);
    r.canonicalize(); a = r;
}

#endif
