// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chain.h>
#include <amount.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << nBits << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "SEC declares Bitcoin a non security 06/07/2018";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

CAmount GetInitialRewards(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 64 * COIN;
    // Subsidy is cut in half every 1,050,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    //On genesis, create 38 million NIX for the Zoin airdrop
    if(nHeight == 1)
        nSubsidy = 38000000 * COIN;

    //stop halving when subsidy reaches 1 coin per block
    if(nSubsidy < (1 * COIN))
        nSubsidy = 1*COIN;

    return nSubsidy;
}


int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees, bool allowInitial) const
{
    int64_t nSubsidy;

    //first block of PoS, add regular block amounts and airdrop amount
    if(!pindexPrev->IsProofOfStake()){
        CAmount nTotal = pindexPrev->nHeight * GetInitialRewards(pindexPrev->nHeight, Params().GetConsensus()) + GetInitialRewards(1, Params().GetConsensus());
        nSubsidy = (nTotal / COIN) * (5 * 1000000) / (365 * 24 * (60 * 60 / nTargetSpacing));
    }else{
        nSubsidy = (pindexPrev->nMoneySupply / COIN) * nCoinYearReward / (365 * 24 * (60 * 60 / nTargetSpacing));
    }

    if(allowInitial && pindexPrev->IsProofOfStake()){
        nSubsidy = (pindexPrev->nMoneySupply / COIN) * (5 * 1000000) / (365 * 24 * (60 * 60 / nTargetSpacing));
    }

    return nSubsidy + nFees;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x4a205f5cd00a449e1b5a93343d759fb2fdbfe3de1b77380eeb04942f9d2579a7"); //block 1
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 6; 
        consensus.SegwitHeight = 6;
        consensus.MinBIP9WarningHeight = 8; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 120;  //2 minute block time
        consensus.nPowTargetTimespan = consensus.nPowTargetSpacing; // Every block
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1475020800; // September 28, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1530415442; // July 1, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000001d880fecdd5e0a8081");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x0000000000000000000f2adce67e49b0b6bdeb9de8b7c3d7e93b21e7fc1e819d"); // 623950

        // ghostnode params
        consensus.nGhostnodeMinimumConfirmations = 1;
        consensus.nGhostnodePaymentsStartBlock = 1080; //1.2 days after mainnet release
        consensus.nGhostnodeInitialize = 800; //~24 hours after mainnet release

        // POS params
        consensus.nPosTimeActivation = 1536779552; //time of PoS activation
        consensus.nPosHeightActivate = 53000;
        nModifierInterval = 10 * 60;    // 10 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        consensus.nCoinMaturityReductionHeight = 97000;
        //Checkpoint to enable ghostfee distribution, fee powered DPoS, 200 conf staking
        consensus.nStartGhostFeeDistribution = 115921;
        consensus.nGhostFeeDistributionCycle = 720;

        consensus.nZerocoinDisableBlock = 205200;
        consensus.nSigmaStartBlock = 232000;

        nMaxTipAge = 30 * 60 * 60; // ~720 blocks behind

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        // new development address - gets paid daily instead of per block, reduces bloat
        consensus.nNewDevelopmentPayoutCycleStartHeight = 179281;
        consensus.nNewDevelopmentPayoutCycle = 720;

        consensus.nStartWitnessLposContracts = 179281;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb9;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0xbe;
        pchMessageStart[3] = 0xf9;
        nDefaultPort = 6214;
        nPruneAfterHeight = 0;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1522615406, 1119233, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41"));
        assert(genesis.hashMerkleRoot == uint256S("0x06c118557a3a44b144a31c9f3a967bd94f94e0d7ff666d30587360f695f0873d"));

        vSeeds.emplace_back("ny.nixplatform.io");
        vSeeds.emplace_back("sf.nixplatform.io");
        vSeeds.emplace_back("fra.nixplatform.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,38);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "nix";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41")},
                { 820, uint256S("0x9d48684e77bc21913aa4c3ea949bb3019ecb33fe7765c08c97e086345cc5aab2")},
                { 1238, uint256S("0x5f9331a6bee682ee1ce5d98386da83a7ecdae65e18c7c2c5c93c483482c0377e")},
                { 47800, uint256S("0xc450d288e8018faae33c669b0fe2dc2dd1a2aa97ee34e263de8964ce8cc7d549")},
                { 61880, uint256S("0xa26727c13a604e3b039b86688ce50a43a45c4647602c2018d4554285fc57c9dc")},
                { 63701, uint256S("0xda1c14665bc14185a4eecfe965b585d1d05218ee5868eb65b154c35f3cd980bb")},
                { 73321, uint256S("0x22a7173b5a74caa5777ff8b36a56f87c3d393cae6bf3fbadf95a847e6d3e011c")},
                { 85191, uint256S("0x7ac4f433832c436c4e5bd19de7d9275e605e75c08d1d468e97b9ea21fc6e7ae6")},
                { 108750, uint256S("0x22712c14439959794cf3af0340757fa2b746ae06a945e8964264bc4b08d9b6ef")},
                { 169900, uint256S("0x6f8b5e85dbb221143f21ddeb4ac59627def0a5eb889cc9b6809ab739e1f56769")},
                { 199296, uint256S("0x7b874564add8e2008e18dfa4435b2924806b0458123e333c3c11b70ca2540ef1")},
                { 208017, uint256S("0xc1f8a8f9eff6a22caa167fbe5043dca2516b176ecbf138b38f5c580b5f4e0590")},
                { 224285, uint256S("0xd82ac4f8293c821e9b2bb507897b5cb6f5908e043dbb6233401c7b2057cf6d92")},
                { 230020, uint256S("0x1ec28a1f6d91aff087b7bc33d0f25d7abd7733e307d5fa56c92490c4bf6a3535")},
                { 241413, uint256S("0x7e6a4dcd210fb2203f7b3ddd583363030ecf3a6c55bb065a55b40d8e54b76dd2")},
                { 242323, uint256S("0xa2c80af800aec5a950189708206e6e3758e3ed0e594b018cc4f1facb0dae9937")},
                { 250881, uint256S("0xca6caf35853762e01a78d08865f3b95bf7b01bd3bfcb430cfd63e7cc9dc6cc46")},
                { 314100, uint256S("0xc1f2cf024c91c9a285bf3e257e8b69145531a269cc00931f521370249dc3f216")},
                { 352132, uint256S("0xf7ff2887cd97f1278ee13a15271c98c3c26a780ae61b6f11d96979bd70bb7b32")},
                { 399211, uint256S("0x06deb41e2f7230f31ca029a7cfb8a49fb3bd29368963e773afabfff3bbb55d36")}
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000000000000f2adce67e49b0b6bdeb9de8b7c3d7e93b21e7fc1e819d
            /* nTime    */ 1581379088,
            /* nTxCount */ 447242,
            /* dTxRate  */ 0.008720599831574105,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 6; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 6; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 2022; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x000000000000056c49030c174179b52a928c870e6e8a822c75973b7970cfbd01"); // 1692000
 
        // ghostnode params
        consensus.nGhostnodeMinimumConfirmations = 1;
        consensus.nGhostnodePaymentsStartBlock = 1000;
        consensus.nGhostnodeInitialize = 950;

        // POS params
        consensus.nPosTimeActivation = 9999999999; //always active
        consensus.nPosHeightActivate = 5;
        nModifierInterval = 10 * 60;    // 10 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        consensus.nCoinMaturityReductionHeight = 5;
        consensus.nStartGhostFeeDistribution = 1000;
        consensus.nGhostFeeDistributionCycle = 20;

        consensus.nStartWitnessLposContracts = 1;
        consensus.nNewDevelopmentPayoutCycleStartHeight = 1;
        consensus.nNewDevelopmentPayoutCycle = 999999999;


        consensus.nZerocoinDisableBlock = 6190;
        consensus.nSigmaStartBlock = 100;


        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 16214;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1522615406, 1119233, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41"));
        assert(genesis.hashMerkleRoot == uint256S("0x06c118557a3a44b144a31c9f3a967bd94f94e0d7ff666d30587360f695f0873d"));

        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet.nixplatform.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,1);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,3);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "tnix";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000000056c49030c174179b52a928c870e6e8a822c75973b7970cfbd01
            /* nTime    */ 1516903490,
            /* nTxCount */ 17082348,
            /* dTxRate  */ 0.09,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP34Height = 1; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 0; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.CSVHeight = 6; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 6; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // ghostnode params
        consensus.nGhostnodePaymentsStartBlock = 9999;
        consensus.nGhostnodeInitialize = 9999;

        // POS params
        consensus.nPosTimeActivation = 9999999999; //always active
        consensus.nPosHeightActivate = 220;
        nModifierInterval = 10 * 60;    // 10 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        nMaxTipAge = 30 * 60 * 60; // ~720 blocks behind

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        consensus.nCoinMaturityReductionHeight = 1;
        consensus.nStartGhostFeeDistribution = 9999;
        consensus.nGhostFeeDistributionCycle = 9999;

        consensus.nStartWitnessLposContracts = 1;
        consensus.nNewDevelopmentPayoutCycleStartHeight = 9999;
        consensus.nNewDevelopmentPayoutCycle = 9999;

        consensus.nZerocoinDisableBlock = 230;
        consensus.nSigmaStartBlock = 235;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 16215;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1522615406, 1119233, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xdd28ad86def767c3cfc34267a950d871fc7462bc57ea4a929fc3596d9b598e41"));
        assert(genesis.hashMerkleRoot == uint256S("0x06c118557a3a44b144a31c9f3a967bd94f94e0d7ff666d30587360f695f0873d"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0xe734db844dfe5a7a06ec42a71c0540f723033830be91bb59524b6e9acbd3345b")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,38);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "rnix";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
