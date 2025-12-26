// required for postman
window = {};
const { jweEncryption } = require("./jwe");

/**
 * Encrypt a request.
 * @param pm The postman object.
 */
encryptRequest = async (pm) => {
	if (typeof pm !== "object" || pm == null) {
		// throwing errors doesn't seem to be working in postman for some reason, so log the error so the user knows
		console.error("'pm' object is invalid");
		throw new Error("'pm' object is invalid");
	}

	if (
		["get", "head", "delete", "options"].includes(
			pm.request.method.toLowerCase(),
		)
	) {
		return;
	}

	const encryptedPayload = await jweEncryption(pm);

	pm.request.body.update(JSON.stringify(encryptedPayload));
};
