// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core.h"
#include "main.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(main_tests)

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    mpq nSum = 0;
    for (int nHeight = 0; nHeight < 14000000; nHeight += 1000) {
        mpq nSubsidy = GetBlockValue(nHeight, 0);
        BOOST_CHECK(nSubsidy <= 50 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK(FormatMoney(nSum) == std::string("20999999.9999999999988615877188902203442921745590865612030029296875"));
}

BOOST_AUTO_TEST_SUITE_END()
