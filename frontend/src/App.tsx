import React, { useState } from "react";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./util/util";

function App() {
  const [credential, setCredential] = useState<PublicKeyCredential | null>(
    null
  );
  const [challenge, setChallenge] = useState<Uint8Array>();
  const [status, setStatus] = useState<string>("");

  async function handleCreateCreds() {
    setStatus("Creating credentials...");
    console.time("createCredentials");
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const publicKey: PublicKeyCredentialCreationOptions = {
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
        authenticatorAttachment: "platform",
      },
      attestation: "direct",
    };

    try {
      console.time("navigatorCredentialsCreate");
      const credential = (await navigator.credentials.create({
        publicKey: publicKey,
      })) as PublicKeyCredential;
      console.timeEnd("navigatorCredentialsCreate");
      setCredential(credential);
      const encodedCredentialId = arrayBufferToBase64(credential.rawId);
      const encodedPublicKey = arrayBufferToBase64(
        (
          credential.response as AuthenticatorAttestationResponse
        ).getPublicKey()!
      );

      try {
        console.time("sendCredentialToBackend");
        const response = await fetch("http://localhost:3002/auth/set-creds", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            credentialId: encodedCredentialId,
            publicKey: encodedPublicKey,
          }),
        });
        console.timeEnd("sendCredentialToBackend");

        if (response.ok) {
          setStatus("Credential data sent to backend successfully");
        } else {
          setStatus("Failed to send credential data to backend");
        }
      } catch (error) {
        setStatus(`Error sending credential data to backend: ${error}`);
      }
    } catch (error) {
      setStatus(`Error creating credential: ${error}`);
    }
    console.timeEnd("createCredentials");
  }

  const handleGetCreds = async () => {
    console.time("getCredentials");
    try {
      console.time("fetchCredentials");
      const response = await fetch("http://localhost:3002/auth/get-creds", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });
      const { credentialId, challenge } = await response.json();
      console.timeEnd("fetchCredentials");

      const publicKey: PublicKeyCredentialRequestOptions = {
        challenge: base64ToArrayBuffer(challenge),
        allowCredentials: [
          {
            id: base64ToArrayBuffer(credentialId), // Remove the '1231' suffix
            type: "public-key",
          },
        ],
        userVerification: "preferred",
      };

      console.time("navigatorCredentialsGet");
      const assertion = (await navigator.credentials.get({ publicKey })) as any;
      console.timeEnd("navigatorCredentialsGet");
      if (!assertion) {
        throw new Error("Failed to get credentials");
      }

      console.time("verifySignature");
      const respons = await fetch(
        "http://localhost:3002/auth/verify-signature",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            clientDataJSON: arrayBufferToBase64(
              assertion.response.clientDataJSON
            ),
            authenticatorData: arrayBufferToBase64(
              assertion.response.authenticatorData
            ),
            signature: arrayBufferToBase64(assertion.response.signature),
          }),
        }
      );
      console.timeEnd("verifySignature");

      if (respons) {
        setStatus("Signature verified successfully");
      } else {
        setStatus("Failed to verify signature");
      }
    } catch (error: any) {
      setStatus(`Error: ${error.message}`);
    }
    console.timeEnd("getCredentials");
  };

  return (
    <div className="App">
      <br />
      <button onClick={handleCreateCreds}> create Creds</button>
      <br />
      <br />
      <button onClick={handleGetCreds}> get Creds</button>
      <br />
      <p>{status}</p>
    </div>
  );
}

export default App;
