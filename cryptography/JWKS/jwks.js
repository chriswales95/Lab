import fs from "fs";
import jose from "node-jose";
import { argv } from "process";

const encryptionKeyId = "rsa-encryption-1";

const generate = async () => {
  let keystore = jose.JWK.createKeyStore();
  await keystore.generate("RSA", 2048, {
    alg: "RSA-OAEP",
    use: "enc",
    kid: encryptionKeyId,
  });

  const output = keystore.toJSON(true);
  console.log(JSON.stringify(output));
  fs.writeFileSync("keystore.json", JSON.stringify(output, null, 2));
  return keystore;
};

const load = async () => {
  if (!fs.existsSync("keystore.json")) {
    console.error("No keystore found. Run 'generate' first.");
    process.exit(1);
  }
  const savedData = JSON.parse(fs.readFileSync("keystore.json", "utf8"));
  const keystore = await jose.JWK.asKeyStore(savedData);
  return keystore;
};

const encrypt = async (message) => {
  const keystore = await load();
  const key = keystore.get(encryptionKeyId);

  const encrypted = await jose.JWE.createEncrypt(
    { format: "compact"},
    key,
  )
    .update(message)
    .final();

  console.log(encrypted);
  return encrypted;
};

const decrypt = async (encryptedMessage) => {
  const keystore = await load();
  const key = keystore.get(encryptionKeyId);

  const decryptedMessage =
    await jose.JWE.createDecrypt(key).decrypt(encryptedMessage);
  const message = decryptedMessage.plaintext.toString();

  console.log(message);
  return message;
};
const outputPrivateKey = async () => {
  const keystore = await load();
  const key = keystore.get(encryptionKeyId);
  const privateKey = key.toJSON(true);
  console.log(JSON.stringify(privateKey));
  return privateKey;
};

const outputPublicKey = async () => {
  const keystore = await load();
  const key = keystore.get(encryptionKeyId);
  const publicKey = key.toJSON();
  console.log(JSON.stringify(publicKey));
  return publicKey;
};

let command = argv[2];
switch (command) {
  case "generate":
    generate();
    break;
  case "encrypt": {
    const message = argv[3];
    if (!message) {
      console.log("Please provide a message to encrypt");
      process.exit(1);
    }
    encrypt(message);
    break;
  }
  case "decrypt": {
    const message = argv[3];
    if (!message) {
      console.log("Please provide a message to decrypt");
      process.exit(1);
    }
    decrypt(message);
    break;
  }
  case "private":
    outputPrivateKey();
    break;
  case "public":
    outputPublicKey();
    break;
  case "help":
    console.log(
      "Commands:\n" +
        "  generate          Generate a new RSA key pair and save to keystore.json\n" +
        "  encrypt <message> Encrypt a message using the public key\n" +
        "  decrypt <message> Decrypt a message using the private key\n" +
        "  private          Output the private key in JWK format\n" +
        "  public           Output the public key in JWK format\n",
    );
    break;
  default:
    console.log(
      "Unknown command. Use 'generate', 'encrypt', 'decrypt', 'private', 'public', or 'help'.",
    );
}
