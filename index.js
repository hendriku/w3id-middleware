require(`${__dirname}/assert`)()

const saml2 = require("saml2-js")
const cookieParser = require("cookie-parser")
const bodyParser = require("body-parser")
const md5 = require("md5")
const moment = require("moment")
const router = require("express").Router()

const X509Cert = `-----BEGIN CERTIFICATE-----\n${process.env.W3ID_CERT}\n-----END CERTIFICATE-----`

const sp_options = {
	entity_id: process.env.W3ID_PARTNER_ID,
	private_key: X509Cert,
	certificate: X509Cert,
	assert_endpoint: process.env.W3ID_IDP_LOGIN_URL
}

const sp = new saml2.ServiceProvider(sp_options)

const idp_options = {
	sso_login_url: process.env.W3ID_IDP_LOGIN_URL,
	certificates: X509Cert,
	allow_unencrypted_assertion: true
}

const idp = new saml2.IdentityProvider(idp_options)

const COOKIES_NEEDED_FOR_VALIDATION = [
	"w3id_name_id",
	"w3id_attributes",
	"w3id_blueGroups",
	"w3id_sessionid",
	"w3id_expiration"
]
const HSTS_HEADER_AGE = 86400

function generateHashForProperties(name_id, sessionID, expiration) {
	if (process.env.NODE_ENV === "development") {
		console.debug("generateHashForProperties arguments:", name_id, sessionID, expiration)
	}
	const STR = `${name_id}-${sessionID}-${expiration}-${process.env.W3ID_SECRET}`
	const hash = md5(STR)

	return hash
}

function clearCookies(res) {
	res.clearCookie("w3id_name_id")
	res.clearCookie("w3id_attributes")
	res.clearCookie("w3id_blueGroups")
	res.clearCookie("w3id_sessionid")
	res.clearCookie("w3id_expiration")
	res.clearCookie("w3id_hash")
	res.clearCookie("w3id_challenge")

	return res
}

function validateSession(req, res, next) {
	if (process.env.NODE_ENV === "development") {
		console.debug("cookies:", req.cookies)
	}

	const NOW = Date.now() / 1000
	const EXPIRATION_TIME =
		req.cookies.w3id_expiration !== undefined ? req.cookies.w3id_expiration / 1000 : -1

	const challenge_flag = req.cookies.w3id_challenge
	const session_hash = req.cookies.w3id_hash

	const thirtyMinutesInMilliseconds = 1000 * 60 * 30

	if (process.env.NODE_ENV === "development") {
		console.debug("challenge_flag", challenge_flag)
	}

	if (challenge_flag) {
		console.debug(
			"'Challenge' flag set (w3id_challenge). Invalidating session and forcing reauthentication."
		)
		clearCookies(res).redirect(req.originalUrl)
	} else if (!session_hash) {
		console.debug("No hash to evaluate for session. Redirecting to login.")
		res.cookie("w3id_redirect", req.originalUrl, {
			httpOnly: false,
			maxAge: thirtyMinutesInMilliseconds
		})
		res.redirect("/__auth")
	} else {
		if (!req.secure) {
			console.debug(
				"WARNING: This request is not secure. Request should be made over encrypted connections to avoid valid credentials falling into nefarious hands."
			)
			console.debug(
				"WARNING: This request is not secure. Strict-Transport-Security header has been set."
			)
			res.set("Strict-Transport-Security", `max-age=${HSTS_HEADER_AGE}`)
		}

		const missing_cookies = COOKIES_NEEDED_FOR_VALIDATION.map(cookieRequired => {
			if (process.env.NODE_ENV === "development") {
				console.debug("Looking for:", cookieRequired)
				console.debug("Found: ", req.cookies[cookieRequired])
			}

			if (!req.cookies[cookieRequired]) {
				return cookieRequired
			}
			return null
		}).filter(isNullValue => isNullValue !== null)
		if (missing_cookies.length > 0) {
			console.debug(
				`Missing cookies required to validate session '${missing_cookies.join(
					"', '"
				)}'. Redirecting to login.`
			)
			res.cookie("w3id_redirect", req.originalUrl, {
				httpOnly: false,
				maxAge: thirtyMinutesInMilliseconds
			})
			res.redirect("/__auth")
		} else if (EXPIRATION_TIME - NOW <= 0) {
			if (process.env.NODE_ENV === "development") {
				console.debug(
					`Session is too old. Invalidating. EXPIRATION_TIME: ${EXPIRATION_TIME} NOW: ${NOW}`
				)
			}

			clearCookies(res).redirect("/__auth")
		} else {
			const hashGeneratedFromCookiesAndSecret = generateHashForProperties(
				decodeURIComponent(req.cookies.w3id_name_id),
				decodeURIComponent(req.cookies.w3id_sessionid),
				decodeURIComponent(req.cookies.w3id_expiration)
			)

			if (process.env.NODE_ENV === "development") {
				console.debug(
					`hashGeneratedFromCookiesAndSecret: ${hashGeneratedFromCookiesAndSecret} session_hash: ${session_hash} eq?: ${
						hashGeneratedFromCookiesAndSecret === session_hash
					}`
				)
			}

			if (hashGeneratedFromCookiesAndSecret !== session_hash) {
				console.debug("Session has been tampered with. Invalidating session.")
				res.cookie("w3id_redirect", req.originalUrl, {
					httpOnly: false,
					maxAge: thirtyMinutesInMilliseconds
				})
				res.redirect("/__auth")
			} else {
				console.debug("Session is valid. Allowing request to continue.")
				res.clearCookie("w3id_redirect")
				res.locals.w3id_name_id = req.cookies.w3id_name_id
				res.locals.attributes = req.cookies.attributes
				res.locals.blueGroups = req.cookies.blueGroups
				next()
			}
		}
	}
}

router.get("/__auth", (req, res) => {
	sp.create_login_request_url(idp, {}, (err, login_url) => {
		if (err !== null) {
			console.debug("GET /__auth ERROR:", err)
			res.status(500).end()
		} else {
			console.debug(login_url)
			res.redirect(login_url)
		}
	})
})

router.post(
	"/__auth",
	bodyParser.json(),
	bodyParser.urlencoded({ extended: false }),
	cookieParser(),
	(req, res) => {
		if (process.env.NODE_ENV === "development") {
			console.debug("req.body:", req.body)
		}

		sp.post_assert(
			idp,
			{
				request_body: {
					RelayState: req.body.RelayState,
					SAMLResponse: req.body.SAMLResponse
				}
			},
			(err, saml_response) => {
				if (err) {
					console.debug("Service provider post_assert error:", err)
					res.status(500)
					res.end()
				} else {
					if (process.env.NODE_ENV === "development") {
						console.debug("saml_response:", saml_response)
					}

					const { name_id } = saml_response.user
					const {
						firstName,
						uid,
						lastName,
						emailaddress,
						cn
					} = saml_response.user.attributes
					const attributes = JSON.stringify({
						firstName,
						lastName,
						uid,
						emailaddress,
						cn
					})
					const blueGroups = JSON.stringify(saml_response.user.attributes.blueGroups)
					const sessionID = saml_response.user.session_index
					const expiration = saml_response.user.session_not_on_or_after

					const propertyHash = generateHashForProperties(name_id, sessionID, expiration)

					const timeUntilExpirationInMilliseconds =
						moment(expiration, "YYYY-MM-DD HH:mm:ss").diff(moment()) - 1

					if (process.env.NODE_ENV === "development") {
						console.debug(
							`COOKIE EXPS >>> expiration: ${expiration} timeUntilExpirationInMilliseconds: ${timeUntilExpirationInMilliseconds}`
						)
						console.debug("name_id:", name_id)
						console.debug("attributes:", attributes)
						console.debug("blueGroups:", blueGroups)
						console.debug("sessionID:", sessionID)
						console.debug("expiration:", expiration)
						console.debug("Setting hash:", propertyHash)
					}

					res.cookie("w3id_name_id", name_id, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})
					res.cookie("w3id_attributes", attributes, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})
					res.cookie("w3id_blueGroups", blueGroups, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})
					res.cookie("w3id_sessionid", sessionID, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})
					res.cookie("w3id_expiration", expiration, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})
					res.cookie("w3id_hash", propertyHash, {
						httpOnly: false,
						maxAge: timeUntilExpirationInMilliseconds
					})

					if (req.cookies.w3id_redirect) {
						const redirectTo = req.cookies.w3id_redirect
						res.redirect(redirectTo)
					} else {
						res.redirect("/")
					}
				}
			}
		)
	}
)

router.all("*", [cookieParser()], validateSession)

module.exports = router
module.exports.generateHashForProperties = generateHashForProperties
