const debug = require("debug")("w3id-middleware:assert")

module.exports = () => {
	const REQUIRED_ENVIRONMENT_VARIABLES = [
		"W3ID_IDP_LOGIN_URL",
		"W3ID_PARTNER_ID",
		"W3ID_CERT",
		"W3ID_SECRET"
	]
	const MISSING_ENVIRONMENT_VARIABLES = REQUIRED_ENVIRONMENT_VARIABLES.map(variable => {
		if (!process.env[variable]) {
			return variable
		}
		return null
	}).filter(isNullValue => isNullValue !== null)

	if (MISSING_ENVIRONMENT_VARIABLES.length > 0) {
		debug(
			`Cannot start app. Missing environment variables '${MISSING_ENVIRONMENT_VARIABLES.join(
				`', '`
			)}' required for W3ID validation. `
		)
		process.exit()
	}

	if (process.env.W3ID_SECRET.length < 72) {
		debug(
			`W3ID_SECRET environment variable is not long enough. It must be at least 72 characters long. Currently, it is ${process.env.W3ID_SECRET.length} characters long.`
		)
		process.exit()
	}
}
