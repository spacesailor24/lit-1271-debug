import { ethers } from "ethers";
import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { createSiweMessage } from "@lit-protocol/auth-helpers";


export async function createEIP1271AuthSig(
    signer: ethers.Wallet,
    contractAddress: string,
    litNodeClient: LitNodeClient
) {
    const siweMessage = await createSiweMessage({
        nonce: await litNodeClient.getLatestBlockhash(),
        walletAddress: signer.address, // Use signer address like working tests
    });

    const signature = await signer.signMessage(siweMessage);

    return {
        address: contractAddress, // Contract address in final auth sig
        sig: signature,
        derivedVia: "EIP1271" as const,
        signedMessage: siweMessage,
    };
}