import { useState } from "react";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./util/util";

function App() {
  const [status, setStatus] = useState<string>("");

  async function handleCreateCredential() {
    setStatus("Creating credential...");
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const publicKeyOptions: PublicKeyCredentialCreationOptions = {
      challenge,
      rp: { name: "Your App" },
      user: {
        id: Uint8Array.from("user_id", (c) => c.charCodeAt(0)),
        name: "user@example.com",
        displayName: "User Name",
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        userVerification: "preferred",
        // authenticatorAttachment:"platform"
      },
      attestation: "direct",
      timeout: 60000,
    };

    try {
      const credential = (await navigator.credentials.create({
        publicKey: publicKeyOptions,
      })) as any;
      const credentialJSON = credential.toJSON();
      const encodedCredentialId = arrayBufferToBase64(credential.rawId);
      const encodedPublicKey = arrayBufferToBase64(
        (
          credential.response as AuthenticatorAttestationResponse
        ).getPublicKey()!
      );

      const response = await fetch(
        "http://localhost:3002/auth/set-credentials",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            credentialId: encodedCredentialId,
            publicKey: encodedPublicKey,
            algorithm: credentialJSON.response.publicKeyAlgorithm,
          }),
        }
      );

      setStatus(
        response.ok
          ? "Credential data sent to backend successfully"
          : "Failed to send credential data to backend"
      );
    } catch (error) {
      setStatus(`Error creating credential: ${error}`);
    }
  }

  async function handleGetCredential() {
    try {
      const response = await fetch(
        "http://localhost:3002/auth/get-credentials",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }
      );
      const { credentialId, challenge } = await response.json();
      if (!credentialId || !challenge) {
        return handleCreateCredential();
      }

      const publicKeyOptions: PublicKeyCredentialRequestOptions = {
        challenge: base64ToArrayBuffer(challenge),
        allowCredentials: [
          {
            id: base64ToArrayBuffer(credentialId),
            type: "public-key",
            // transports: ["internal"],
          },
        ],
        userVerification: "preferred",
      };

      const assertion = (await navigator.credentials.get({
        publicKey: publicKeyOptions,
      })) as PublicKeyCredential;

      const verificationResponse = await fetch(
        "http://localhost:3002/auth/verify-signature",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            clientDataJSON: arrayBufferToBase64(
              assertion.response.clientDataJSON
            ),
            authenticatorData: arrayBufferToBase64(
              (assertion.response as AuthenticatorAssertionResponse)
                .authenticatorData
            ),
            signature: arrayBufferToBase64(
              (assertion.response as AuthenticatorAssertionResponse).signature
            ),
          }),
        }
      );

      setStatus(
        verificationResponse.ok
          ? "Signature verified successfully"
          : "Failed to verify signature"
      );
    } catch (error: any) {
      console.log(error);
      setStatus(`Error: ${error.message}`);
      return handleCreateCredential();
    }
  }
  return (
    <div className="App">
      <br />
      <button onClick={handleGetCredential}>Get Credential</button>
      <br />
      <p>{status}</p>
    </div>
  );
}
export default App;
