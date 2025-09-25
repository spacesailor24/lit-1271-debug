import { LIT_NETWORK, LIT_RPC } from "@lit-protocol/constants";
import { LitContracts } from "@lit-protocol/contracts-sdk";
import { LitNodeClient } from "@lit-protocol/lit-node-client";
import { ethers } from "ethers";

const { ETHEREUM_PRIVATE_KEY } = process.env;

const NETWORK = LIT_NETWORK.DatilDev;

(async () => {
    const litNodeClient = new LitNodeClient({
        litNetwork: NETWORK,
        debug: false,
    });
    await litNodeClient.connect();

    try {
        const ethersWallet = new ethers.Wallet(
            ETHEREUM_PRIVATE_KEY!,
            new ethers.providers.JsonRpcProvider(LIT_RPC.CHRONICLE_YELLOWSTONE)
        );

        const litContracts = new LitContracts({
            signer: ethersWallet,
            network: NETWORK,
            debug: false,
        });
        await litContracts.connect();

        const pkp = (await litContracts.pkpNftContractUtils.write.mint()).pkp;
        console.log('pkp', pkp);
    } finally {
        await litNodeClient.disconnect();
    }
})();