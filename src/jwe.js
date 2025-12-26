const jose = require("node-jose");
const { validateEnv } = require("./util");

function jweEncryption(pm) {
	validateEnv(["MLE_KEY_ID", "MLE_ENCRYPTION_CERT"], pm.environment);

	return new Promise((resolve) => {
		const reqBody = pm.request.body.raw;
		const keyId = pm.environment.get("MLE_KEY_ID");
		const encryptionCertificate = pm.environment.get("MLE_ENCRYPTION_CERT");

		const key = `-----BEGIN CERTIFICATE-----\n${encryptionCertificate}\n-----END CERTIFICATE-----`;
		const keystore = jose.JWK.createKeyStore();
		return (
			keystore
				.add(key, "pem", {
					alg: "RSA-OAEP-256",
					cty: "Application/JSON",
					enc: "A128GCM",
					kid: keyId,
				})

				// Encrypt payload and attach to request body
				.then((publicKey) => {
					return jose.JWE.createEncrypt(
						{
							format: "compact",
							fields: {
								enc: "A128GCM",
								iat: Date.now(),
							},
						},
						publicKey,
					)
						.update(reqBody)
						.final();
				})
				.then((encrypted) => {
					resolve({ encData: encrypted });
				})
		);
	});
}

function jweDecryption(pm) {
	validateEnv(["MLE_DECRYPTION_KEY"], pm.environment);

	return new Promise((resolve) => {
		const responseBody = pm.response.body;
		const decryptionKey = pm.environment.get("MLE_DECRYPTION_KEY");

		const key = `-----BEGIN PRIVATE KEY-----\n${decryptionKey}\n-----END PRIVATE KEY-----`;
		const keystore = jose.JWK.createKeyStore();
		return (
			keystore
				.add(key, "pem")
				// Decrypt payload and attach to response body
				.then((privateKey) => {
					return jose.JWE.createDecrypt(privateKey).decrypt(responseBody);
				})
				.then((decrypted) => {
					resolve(decrypted.payload.toString());
				})
		);
	});
}

module.exports = {
	jweEncryption,
	jweDecryption,
};
