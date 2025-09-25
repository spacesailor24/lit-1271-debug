# EIP-1271 Signing Test with Lit Protocol

This project tests EIP-1271 smart contract signature validation with Lit Protocol nodes. It demonstrates partial compatibility between smart contract wallets and Lit Protocol's authentication system.

## Quick Setup

1. **Install dependencies**:
   ```bash
   pnpm install
   ```

2. **Copy environment file**:
   ```bash
   cp .env.example .env
   ```

   The `.env` file contains a pre-deployed contract address and whitelisted signer keys, so no deployment is needed.

3. **Run the tests**:
   ```bash
   # Test EIP-1271 decryption (works)
   pnpm run test:decryption

   # Test EIP-1271 session signatures (partial success)
   pnpm run test:session
   ```

## Test Results

### Decryption Test (`pnpm run test:decryption`)

**Expected Result**: **SUCCESS** - Complete end-to-end EIP-1271 validation

This test demonstrates that Lit Protocol nodes can successfully:
- Validate EIP-1271 signatures from smart contracts
- Use contract-based authentication for direct operations like decryption
- Handle the `derivedVia: "EIP1271"` authentication format correctly

The test will show:
```
🔓 Testing decryption with VALID signer...
📋 Contract validation: ✅ VALID
✅ SUCCESS! Valid signer decryption works
📋 Decrypted: "Test data for EIP-1271 decryption"

🔓 Testing decryption with VALID signer...
📋 Contract validation: ✅ VALID
✅ SUCCESS! Valid signer 2 decryption works
📋 Decrypted: "Test data for EIP-1271 decryption"

🔍 SANITY CHECK: Testing with INVALID signer (should fail)...
📋 Invalid signer: 0xAa9607e954F0e5B2b520d51a2Eec52c9e83ef4D5
✅ SANITY CHECK PASSED: Invalid signer correctly rejected
📋 Error (expected): There was an error getting the signing shares from the nodes. Response from the nodes: {"success":false,"error":{"errorKind":"Validation","errorCode":...

🎉 ALL TESTS PASSED!
📋 EIP-1271 contract validation is working correctly
```

### Session Signatures Test (`pnpm run test:session`)

**Expected Result**: **PARTIAL SUCCESS** - Session creation works, Lit Action execution fails

This test shows a limitation in Lit Protocol's EIP-1271 support:
- Session signature creation succeeds with EIP-1271 auth
- Lit Action execution fails with capability validation error

The test will show:
```
🔐 Creating EIP-1271 auth signature...
📋 Contract validation: ✅ VALID

🔗 Creating session signatures with EIP-1271 auth...
✅ SUCCESS! Session signatures created with EIP-1271 auth
📋 Session signatures count: 3

⚡ Testing Lit Action execution...

[Lit-JS-SDK v7.3.1] [2025-09-25T07:05:50.048Z] [ERROR] [core] [id: 16c7356f8d291] most common error: {"errorKind":"Validation","errorCode":"NodeSIWECapabilityInvalid","status":400,"message":"Invalid Capability object in SIWE resource ReCap","correlationId":"lit_16c7356f8d291","details":["validation error: Resource id not found in auth_sig capabilities: validation error: Could not find valid capability.","Resource id not found in auth_sig capabilities"]}

❌ Test failed: There was an error getting the signing shares from the nodes. Response from the nodes: {"success":false,"error":{"errorKind":"Validation","errorCode":"NodeSIWECapabilityInvalid","status":400,"message":"Invalid Capability object in SIWE resource ReCap","correlationId":"lit_16c7356f8d291","details":["validation error: Resource id not found in auth_sig capabilities: validation error: Could not find valid capability.","Resource id not found in auth_sig capabilities"]}}: [object Object]
```

## Why Session Signatures Fail While Decryption Works

The difference in behavior stems from Lit Protocol's internal validation:

- **Direct operations** (like `decryptToString`): Lit nodes validate the EIP-1271 signature directly against the smart contract. This works perfectly.

- **Session-based operations** (like `executeJs`): Lit nodes perform additional capability validation that appears to have limitations with EIP-1271 signatures, resulting in `NodeSIWECapabilityInvalid` errors.

This suggests Lit Protocol has **partial EIP-1271 support** - sufficient for direct authentication but not for session-based execution capabilities.

## Project Structure

- **eip1271-decryption-test.ts**: Working EIP-1271 decryption test
- **eip1271-session-test.ts**: Session signature test (demonstrates error)
- **src/SimpleEIP1271.sol**: EIP-1271 smart contract with signer whitelist
- **verify-eip-1271-signature.ts**: Contract signature verification utility
- **create-eip-1271-auth-sig.ts**: Auth signature creation utility

## Makefile Commands (Optional)

If you need to deploy your own contract or make modifications:

```bash
# Install Foundry dependencies
make install

# Run contract tests
make test

# Deploy to Yellowstone RPC
make deploy
```

**Note**: The environment already includes a working deployed contract, so these commands are only needed for development or custom deployments.

## Environment Variables

- `EIP_1271_WHITELIST_CONTRACT_ADDRESS`: Smart contract address (pre-configured)
- `EIP_1271_WHITELISTED_SIGNER_*_PRIVATE_KEY`: Whitelisted signer keys (pre-configured)
- `FORGE_DEPLOYMENT_RPC_URL`: Yellowstone RPC URL for deployment
- `FORGE_DEPLOYMENT_PRIVATE_KEY`: Deployment wallet private key (can be any private key)
