import { createLitClient } from "@lit-protocol/lit-client";
import { createAuthManager, storagePlugins } from "@lit-protocol/auth";
import { nagaDev } from "@lit-protocol/networks";
import { createAccBuilder } from "@lit-protocol/access-control-conditions";
import { ethers } from "ethers";
import { createSiweMessage } from "@lit-protocol/auth-helpers";
import { privateKeyToAccount } from "viem/accounts";

const {
    EIP_1271_WHITELIST_CONTRACT_ADDRESS,
    EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY,
    EIP_1271_WHITELISTED_SIGNER_2_PRIVATE_KEY,
} = process.env;

const TEST_DATA = 'Test data for EIP-1271 decryption';

// Helper to get nonce from the blockchain
async function getLatestBlockhash(provider: ethers.providers.Provider): Promise<string> {
    const latestBlock = await provider.getBlock('latest');
    return latestBlock.hash;
}

async function createEIP1271AuthSig(
    signer: ethers.Wallet,
    contractAddress: string,
    provider: ethers.providers.Provider
) {
    const nonce = await getLatestBlockhash(provider);

    const siweMessage = await createSiweMessage({
        walletAddress: signer.address,
        nonce: nonce,
    });

    const signature = await signer.signMessage(siweMessage);

    return {
        address: contractAddress,
        sig: signature,
        derivedVia: "EIP1271" as const,
        signedMessage: siweMessage,
    };
}

async function verifyEIP1271Signature(
    contractAddress: string,
    message: string,
    signature: string,
    provider: ethers.providers.Provider
): Promise<boolean> {
    const contract = new ethers.Contract(
        contractAddress,
        ["function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4)"],
        provider
    );

    try {
        // Use hashMessage to get the same hash that wallet.signMessage creates
        // This includes the Ethereum message prefix
        const messageHash = ethers.utils.hashMessage(message);
        const result = await contract.isValidSignature(messageHash, signature);
        return result === "0x1626ba7e"; // EIP-1271 magic value
    } catch (error) {
        return false;
    }
}

async function attemptDecryption(
    litClient: any,
    authManager: any,
    encryptedData: any,
    authSig: any,
    dummyAccount: any
) {
    const builder = createAccBuilder();
    const accs = builder
        .evmBasic({
            contractAddress: "",
            standardContractType: "",
            chain: "yellowstone",
            method: "",
            parameters: [":userAddress"],
            returnValueTest: {
                comparator: "=",
                value: EIP_1271_WHITELIST_CONTRACT_ADDRESS!
            }
        })
        .build();

    // Create a minimal EOA auth context for the dummy account
    // We'll override this with the EIP-1271 authSig
    const dummyAuthContext = await authManager.createEoaAuthContext({
        config: {
            account: dummyAccount,
        },
        authConfig: {
            resources: [['access-control-condition-decryption', '*']],
            expiration: new Date(Date.now() + 1000 * 60 * 15).toISOString(),
        },
        litClient: litClient,
    });

    const decryptedResponse = await litClient.decrypt({
        ciphertext: encryptedData.ciphertext,
        dataToEncryptHash: encryptedData.dataToEncryptHash,
        unifiedAccessControlConditions: accs,
        chain: "yellowstone",
        authContext: dummyAuthContext,
        // Pass the EIP-1271 authSig - this should override the authContext's authSig
        authSig: authSig,
    });

    return decryptedResponse.convertedData || decryptedResponse.decryptedData;
}

async function testEIP1271Decryption() {
    if (!EIP_1271_WHITELIST_CONTRACT_ADDRESS) {
        throw new Error("EIP_1271_WHITELIST_CONTRACT_ADDRESS environment variable is required");
    }

    // Create the Lit client
    const litClient = await createLitClient({ network: nagaDev });

    // Create auth manager for storage
    const authManager = createAuthManager({
        storage: storagePlugins.localStorageNode({
            appName: 'eip1271-decryption-test',
            networkName: 'naga-dev',
            storagePath: './.lit-auth-local',
        }),
    });

    try {
        // Setup
        const provider = new ethers.providers.JsonRpcProvider("https://yellowstone-rpc.litprotocol.com");
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

        // Create a dummy Viem account for the auth context
        // This is needed because v8 requires an authContext, but we'll override with EIP-1271 authSig
        const dummyAccount = privateKeyToAccount('0x1234567890123456789012345678901234567890123456789012345678901234');
        console.log(`Dummy account: ${dummyAccount.address}`);

        // 1. Encrypt test data
        console.log("Encrypting test data...");

        const builder = createAccBuilder();
        const accs = builder
            .evmBasic({
                contractAddress: "",
                standardContractType: "",
                chain: "yellowstone",
                method: "",
                parameters: [":userAddress"],
                returnValueTest: {
                    comparator: "=",
                    value: EIP_1271_WHITELIST_CONTRACT_ADDRESS
                }
            })
            .build();

        const encryptedData = await litClient.encrypt({
            dataToEncrypt: TEST_DATA,
            unifiedAccessControlConditions: accs,
            chain: "yellowstone",
        });

        if (!encryptedData.ciphertext || !encryptedData.dataToEncryptHash) {
            throw new Error("Encryption failed");
        }
        console.log("Data encrypted successfully");

        // 2. Test with valid signer 1
        console.log("Testing decryption with VALID signer 1...");
        const validSigner = whitelistedSigners[0];
        const validAuthSig = await createEIP1271AuthSig(validSigner, EIP_1271_WHITELIST_CONTRACT_ADDRESS, provider);

        // Verify signature with contract
        const isValidSignature = await verifyEIP1271Signature(
            EIP_1271_WHITELIST_CONTRACT_ADDRESS,
            validAuthSig.signedMessage,
            validAuthSig.sig,
            provider
        );
        console.log(`Contract validation: ${isValidSignature ? "VALID" : "INVALID"}`);

        if (!isValidSignature) {
            throw new Error("EIP-1271 signature validation failed");
        }

        // Attempt decryption with valid signer
        const decryptRes = await attemptDecryption(litClient, authManager, encryptedData, validAuthSig, dummyAccount);

        if (decryptRes !== TEST_DATA) {
            throw new Error(`Expected: "${TEST_DATA}", got: "${decryptRes}"`);
        }

        console.log("SUCCESS! Valid signer 1 decryption works");
        console.log(`Decrypted: "${decryptRes}"`);

        // 2.1. Test with valid signer 2 (if available)
        if (whitelistedSigners.length > 1) {
            console.log("Testing decryption with VALID signer 2...");
            const validSigner2 = whitelistedSigners[1];
            const validAuthSig2 = await createEIP1271AuthSig(validSigner2, EIP_1271_WHITELIST_CONTRACT_ADDRESS, provider);

            // Verify signature with contract
            const isValidSignature2 = await verifyEIP1271Signature(
                EIP_1271_WHITELIST_CONTRACT_ADDRESS,
                validAuthSig2.signedMessage,
                validAuthSig2.sig,
                provider
            );
            console.log(`Contract validation: ${isValidSignature2 ? "VALID" : "INVALID"}`);

            if (!isValidSignature2) {
                throw new Error("EIP-1271 signature validation failed for signer 2");
            }

            // Attempt decryption with valid signer 2
            const decryptRes2 = await attemptDecryption(litClient, authManager, encryptedData, validAuthSig2, dummyAccount);

            if (decryptRes2 !== TEST_DATA) {
                throw new Error(`Expected: "${TEST_DATA}", got: "${decryptRes2}"`);
            }

            console.log("SUCCESS! Valid signer 2 decryption works");
            console.log(`Decrypted: "${decryptRes2}"`);
        }

        // 3. Sanity check with invalid signer
        console.log("SANITY CHECK: Testing with INVALID signer (should fail)...");
        const invalidSigner = ethers.Wallet.createRandom().connect(provider);
        console.log(`Invalid signer: ${invalidSigner.address}`);

        const invalidAuthSig = await createEIP1271AuthSig(invalidSigner, EIP_1271_WHITELIST_CONTRACT_ADDRESS, provider);

        try {
            const invalidDecryptRes = await attemptDecryption(litClient, authManager, encryptedData, invalidAuthSig, dummyAccount);
            throw new Error(`SANITY CHECK FAILED: Invalid signer should not succeed! Got: "${invalidDecryptRes}"`);
        } catch (error: any) {
            if (error.message?.includes('SANITY CHECK FAILED')) {
                throw error;
            }

            // Expected failure - invalid signer should be rejected
            console.log("SANITY CHECK PASSED: Invalid signer correctly rejected");
            console.log(`Error (expected): ${error.message ? error.message.substring(0, 150) : error}...`);
        }

        console.log("ALL TESTS PASSED!");
        console.log("EIP-1271 contract validation is working correctly");

    } catch (error) {
        console.error("Test failed:", error);
        throw error;
    }
}

(async () => {
    try {
        await testEIP1271Decryption();
    } catch (error) {
        process.exit(1);
    }
})();
