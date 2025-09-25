import { LIT_NETWORK, LIT_RPC, LIT_ABILITY } from "@lit-protocol/constants";
import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { LitActionResource } from "@lit-protocol/auth-helpers";
import { ethers } from "ethers";

import { verifyEIP1271Signature } from "./verify-eip-1271-signature";
import { createEIP1271AuthSig } from "./create-eip-1271-auth-sig";

const {
    EIP_1271_WHITELIST_CONTRACT_ADDRESS,
    EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY,
} = process.env;

const NETWORK = LIT_NETWORK.DatilDev;

async function testEIP1271SessionSignatures() {
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

        if (whitelistedSigners.length === 0) {
            throw new Error("At least one whitelisted signer private key is required");
        }

        // 1. Create EIP-1271 auth signature using working format from decryption test
        console.log("🔐 Creating EIP-1271 auth signature...");
        const signer = whitelistedSigners[0];
        const eip1271AuthSig = await createEIP1271AuthSig(signer, EIP_1271_WHITELIST_CONTRACT_ADDRESS, litNodeClient);

        // 2. Verify the signature works with the contract
        const isValid = await verifyEIP1271Signature(
            EIP_1271_WHITELIST_CONTRACT_ADDRESS,
            eip1271AuthSig.signedMessage,
            eip1271AuthSig.sig,
            provider
        );

        console.log(`📋 Contract validation: ${isValid ? "✅ VALID" : "❌ INVALID"}`);

        if (!isValid) {
            throw new Error("EIP-1271 signature validation failed");
        }

        // 3. Create session signatures with EIP-1271 auth
        console.log("\n🔗 Creating session signatures with EIP-1271 auth...");
        const sessionSigs = await litNodeClient.getSessionSigs({
            chain: "ethereum",
            expiration: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(),
            resourceAbilityRequests: [
                {
                    resource: new LitActionResource("*"),
                    ability: LIT_ABILITY.LitActionExecution,
                },
            ],
            authNeededCallback: async () => {
                return eip1271AuthSig;
            },
        });

        console.log("✅ SUCCESS! Session signatures created with EIP-1271 auth");
        console.log(`📋 Session signatures count: ${Object.keys(sessionSigs).length}`);

        // 4. Test Lit Action execution with session signatures
        console.log("\n⚡ Testing Lit Action execution...");
        const result = await litNodeClient.executeJs({
            sessionSigs,
            code: `(() => {
                console.log('Hello from Lit Protocol!');
                Lit.Actions.setResponse({
                    response: JSON.stringify({ message: 'Hello from Lit Protocol with EIP-1271!' }),
                });
            })()`,
            jsParams: {},
        });

        console.log("✅ SUCCESS! Lit Action executed with EIP-1271 session signatures");
        console.log(`📋 Result: ${JSON.stringify(result.response, null, 2)}`);

        console.log("\n🎉 ALL TESTS PASSED!");
        console.log("📋 EIP-1271 session signatures working end-to-end");

    } catch (error: any) {
        console.error("❌ Test failed:", error.message || error);
        throw error;
    } finally {
        await litNodeClient.disconnect();
    }
}

(async () => {
    try {
        await testEIP1271SessionSignatures();
    } catch (error) {
        process.exit(1);
    }
})();