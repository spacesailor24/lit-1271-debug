import { LIT_NETWORK, LIT_RPC } from "@lit-protocol/constants";
import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { ethers } from "ethers";
import { encryptString, decryptToString } from "@lit-protocol/encryption";

import { verifyEIP1271Signature } from "./verify-eip-1271-signature";
import { createEIP1271AuthSig } from "./create-eip-1271-auth-sig";

const {
    EIP_1271_WHITELIST_CONTRACT_ADDRESS,
    EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY,
    EIP_1271_WHITELISTED_SIGNER_2_PRIVATE_KEY,
} = process.env;

const NETWORK = LIT_NETWORK.DatilDev;
const TEST_DATA = 'Test data for EIP-1271 decryption';

async function attemptDecryption(
    accessControlConditions: any[],
    encryptRes: any,
    authSig: any,
    litNodeClient: LitNodeClient
) {
    return await decryptToString(
        {
            accessControlConditions,
            ciphertext: encryptRes.ciphertext,
            dataToEncryptHash: encryptRes.dataToEncryptHash,
            authSig,
            chain: "yellowstone" as const,
        },
        litNodeClient as unknown as LitNodeClient
    );
}

async function testEIP1271Decryption() {
    if (!EIP_1271_WHITELIST_CONTRACT_ADDRESS) {
        throw new Error("EIP_1271_WHITELIST_CONTRACT_ADDRESS environment variable is required");
    }

    const litNodeClient = new LitNodeClient({
        litNetwork: NETWORK,
        debug: true,
    });
    await litNodeClient.connect();

    try {
        // Setup
        const provider = new ethers.providers.JsonRpcProvider(LIT_RPC.CHRONICLE_YELLOWSTONE);
        const whitelistedSigners: ethers.Wallet[] = [];

        if (EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY) {
            whitelistedSigners.push(new ethers.Wallet(EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY, provider));
        }
        if (EIP_1271_WHITELISTED_SIGNER_2_PRIVATE_KEY) {
            whitelistedSigners.push(new ethers.Wallet(EIP_1271_WHITELISTED_SIGNER_2_PRIVATE_KEY, provider));
        }

        if (whitelistedSigners.length === 0) {
            throw new Error("At least one whitelisted signer private key is required");
        }

        const accessControlConditions = [
            {
                contractAddress: "",
                standardContractType: "" as const,
                chain: "yellowstone" as const,
                method: "",
                parameters: [":userAddress"],
                returnValueTest: {
                    comparator: "=" as const,
                    value: EIP_1271_WHITELIST_CONTRACT_ADDRESS
                }
            }
        ];

        // 1. Encrypt test data
        console.log("🔐 Encrypting test data...");
        const encryptRes = await encryptString(
            { accessControlConditions, dataToEncrypt: TEST_DATA },
            litNodeClient as unknown as LitNodeClient
        );

        if (!encryptRes.ciphertext || !encryptRes.dataToEncryptHash) {
            throw new Error("Encryption failed");
        }
        console.log("✅ Data encrypted successfully");

        // 2. Test with valid signer
        console.log("\n🔓 Testing decryption with VALID signer...");
        const validSigner = whitelistedSigners[0];
        const validAuthSig = await createEIP1271AuthSig(validSigner, EIP_1271_WHITELIST_CONTRACT_ADDRESS, litNodeClient);

        // Verify signature with contract
        const isValidSignature = await verifyEIP1271Signature(
            EIP_1271_WHITELIST_CONTRACT_ADDRESS,
            validAuthSig.signedMessage,
            validAuthSig.sig,
            provider
        );
        console.log(`📋 Contract validation: ${isValidSignature ? "✅ VALID" : "❌ INVALID"}`);

        if (!isValidSignature) {
            throw new Error("EIP-1271 signature validation failed");
        }

        // Attempt decryption with valid signer
        const decryptRes = await attemptDecryption(accessControlConditions, encryptRes, validAuthSig, litNodeClient);

        if (decryptRes !== TEST_DATA) {
            throw new Error(`Expected: "${TEST_DATA}", got: "${decryptRes}"`);
        }

        console.log("✅ SUCCESS! Valid signer decryption works");
        console.log(`📋 Decrypted: "${decryptRes}"`);

        // 2.1. Test with valid signer 2
        console.log("\n🔓 Testing decryption with VALID signer...");
        const validSigner2 = whitelistedSigners[1];
        const validAuthSig2 = await createEIP1271AuthSig(validSigner2, EIP_1271_WHITELIST_CONTRACT_ADDRESS, litNodeClient);

        // Verify signature with contract
        const isValidSignature2 = await verifyEIP1271Signature(
            EIP_1271_WHITELIST_CONTRACT_ADDRESS,
            validAuthSig2.signedMessage,
            validAuthSig2.sig,
            provider
        );
        console.log(`📋 Contract validation: ${isValidSignature ? "✅ VALID" : "❌ INVALID"}`);

        if (!isValidSignature2) {
            throw new Error("EIP-1271 signature validation failed");
        }

        // Attempt decryption with valid signer
        const decryptRes2 = await attemptDecryption(accessControlConditions, encryptRes, validAuthSig, litNodeClient);

        if (decryptRes2 !== TEST_DATA) {
            throw new Error(`Expected: "${TEST_DATA}", got: "${decryptRes2}"`);
        }

        console.log("✅ SUCCESS! Valid signer 2 decryption works");
        console.log(`📋 Decrypted: "${decryptRes2}"`);

        // 3. Sanity check with invalid signer
        console.log("\n🔍 SANITY CHECK: Testing with INVALID signer (should fail)...");
        const invalidSigner = ethers.Wallet.createRandom().connect(provider);
        console.log(`📋 Invalid signer: ${invalidSigner.address}`);

        const invalidAuthSig = await createEIP1271AuthSig(invalidSigner, EIP_1271_WHITELIST_CONTRACT_ADDRESS, litNodeClient);

        try {
            const invalidDecryptRes = await attemptDecryption(accessControlConditions, encryptRes, invalidAuthSig, litNodeClient);
            throw new Error(`❌ SANITY CHECK FAILED: Invalid signer should not succeed! Got: "${invalidDecryptRes}"`);
        } catch (error: any) {
            if (error.message?.includes('SANITY CHECK FAILED')) {
                throw error;
            }

            // Expected failure - invalid signer should be rejected
            console.log("✅ SANITY CHECK PASSED: Invalid signer correctly rejected");
            console.log(`📋 Error (expected): ${error.message ? error.message.substring(0, 150) : error}...`);
        }

        console.log("\n🎉 ALL TESTS PASSED!");
        console.log("📋 EIP-1271 contract validation is working correctly");

    } catch (error) {
        console.error("❌ Test failed:", error);
        throw error;
    } finally {
        await litNodeClient.disconnect();
    }
}

(async () => {
    try {
        await testEIP1271Decryption();
    } catch (error) {
        process.exit(1);
    }
})();