import { ethers } from "ethers";

export async function verifyEIP1271Signature(
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
