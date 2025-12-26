/**
 * Validates if the required variables are available in the environment
 * @param {*} requiredVariables The list of required variables
 * @param {*} env The postman environment
 */
function validateEnv(requiredVariables, env) {
  const missing = requiredVariables.filter((k) => !env.get(k));

  if (missing.length) {
    console.error(`These environment variables are required: ${missing}`);
    throw new Error(`These environment variables are required: ${missing}`);
  }
}

module.exports = {
  validateEnv,
};
