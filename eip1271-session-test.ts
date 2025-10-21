import { LIT_NETWORK, LIT_RPC, LIT_ABILITY } from "@lit-protocol/constants";
import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { LitActionResource, createSiweMessage, LitResourceAbilityRequest } from "@lit-protocol/auth-helpers";
import { ethers } from "ethers";

const {
    EIP_1271_WHITELIST_CONTRACT_ADDRESS,
    EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY,
} = process.env;

const NETWORK = LIT_NETWORK.DatilDev;

async function createEIP1271AuthSig(
    signer: ethers.Wallet,
    contractAddress: string,
    litNodeClient: LitNodeClient,
    chainId: number,
    uri?: string,
    expiration?: string,
    resourceAbilityRequests?: LitResourceAbilityRequest[],
) {
    const siweMessage = await createSiweMessage({
        nonce: await litNodeClient.getLatestBlockhash(),
        walletAddress: signer.address, // Use signer address like working tests
        chainId,
        uri,
        expiration,
        resources: resourceAbilityRequests,
        litNodeClient,
    });

    const signature = await signer.signMessage(siweMessage);

    return {
        address: contractAddress, // Contract address in final auth sig
        sig: signature,
        derivedVia: "EIP1271" as const,
        signedMessage: siweMessage,
    };
}

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
        const { chainId } = await provider.getNetwork();
        const whitelistedSigners: ethers.Wallet[] = [];

        if (EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY) {
            whitelistedSigners.push(new ethers.Wallet(EIP_1271_WHITELISTED_SIGNER_1_PRIVATE_KEY, provider));
        }

        if (whitelistedSigners.length === 0) {
            throw new Error("At least one whitelisted signer private key is required");
        }

        // Create session signatures with EIP-1271 auth
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
            authNeededCallback: async ({
                uri,
                expiration,
                resourceAbilityRequests,
            }) => {
                return await createEIP1271AuthSig(
                    whitelistedSigners[0],
                    EIP_1271_WHITELIST_CONTRACT_ADDRESS,
                    litNodeClient,
                    chainId,
                    uri,
                    expiration,
                    resourceAbilityRequests
                );
            },
        });

        console.log("✅ SUCCESS! Session signatures created with EIP-1271 auth");
        console.log(`📋 Session signatures count: ${Object.keys(sessionSigs).length}`);

        // Test Lit Action execution with session signatures
        console.log("\n⚡ Testing Lit Action execution...");
        const result = await litNodeClient.executeJs({
            sessionSigs,
            code: `(() => {
                Lit.Actions.setResponse({
                    response: JSON.stringify({ authSigAddress: Lit.Auth.authSigAddress }),
                });
            })()`,
            jsParams: {},
        });

        const authSigAddress = JSON.parse(result.response as string).authSigAddress;
        if (authSigAddress !== EIP_1271_WHITELIST_CONTRACT_ADDRESS) {
            throw new Error(
                `The recovered address ${authSigAddress} does not match the EIP-1271 contract address ${EIP_1271_WHITELIST_CONTRACT_ADDRESS}`
            );
        }

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