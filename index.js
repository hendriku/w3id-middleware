require(`${__dirname}/assert`)();



const debug = require('debug')('w3id-middleware:index');
const saml2 = require('saml2-js');

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const md5 = require('md5');
const moment = require('moment');

const router = require('express').Router();

console.log("Welcome to custom w3id-middleware")
debug("!!! Imported custom w3id-middleware");

const X509Cert = "-----BEGIN CERTIFICATE-----\n" + process.env.W3ID_CERT + "\n-----END CERTIFICATE-----";
const SAML_CONFIG = {
    path: '/__auth',
    entryPoint: process.env.W3ID_IDP_LOGIN_URL,
    issuer: process.env.W3ID_PARTNER_ID,
    cert : X509Cert,
};

const sp_options = {
    entity_id: process.env.W3ID_PARTNER_ID,
    private_key: X509Cert,
    certificate: X509Cert,
    assert_endpoint: process.env.W3ID_IDP_LOGIN_URL
};

const sp = new saml2.ServiceProvider(sp_options);

const idp_options = {
    sso_login_url: process.env.W3ID_IDP_LOGIN_URL,
    certificates: X509Cert,
    allow_unencrypted_assertion : true
};

const idp = new saml2.IdentityProvider(idp_options);

const COOKIES_NEEDED_FOR_VALIDATION = ['w3id_userid', 'w3id_sessionid', 'w3id_expiration'];
const HSTS_HEADER_AGE = 86400;

function generateHashForProperties(userID, sessionID, expiration){

    if(process.env.NODE_ENV === 'development'){
        debug('generateHashForProperties arguments:', userID, sessionID, expiration);
    }
    const STR = `${userID}-${sessionID}-${expiration}-${process.env.W3ID_SECRET}`;
    const hash = md5(STR);

    return hash;
}

function clearCookies(res){

    res.clearCookie( 'w3id_userid' );
    res.clearCookie( 'w3id_sessionid' );
    res.clearCookie( 'w3id_expiration' );
    res.clearCookie( 'w3id_hash' );
    res.clearCookie( 'w3id_challenge' );

    return res;

}

function validateSession(req, res, next){

    if(process.env.NODE_ENV === 'development'){
        debug('cookies:', req.cookies);
    }

    const NOW = Date.now() / 1000;
    const EXPIRATION_TIME = req.cookies['w3id_expiration'] !== undefined ? req.cookies['w3id_expiration'] / 1000 : -1;

    const challenge_flag = req.cookies['w3id_challenge'];
    const session_hash = req.cookies['w3id_hash'];

    const thirtyMinutesInMilliseconds = 1000 * 60 * 30;

    if(process.env.NODE_ENV === 'development'){
        debug('challenge_flag', challenge_flag);
    }

    if(challenge_flag){

        debug(`'Challenge' flag set (w3id_challenge). Invalidating session and forcing reauthentication.`);
        clearCookies(res).redirect(req.originalUrl);

    } else if(!session_hash){
        debug('No hash to evaluate for session. Redirecting to login.');
        res.cookie( 'w3id_redirect', req.originalUrl, { httpOnly : false, maxAge : thirtyMinutesInMilliseconds } );
        res.redirect('/__auth');
    } else {

        if(!req.secure){
            debug('WARNING: This request is not secure. Request should be made over encrypted connections to avoid valid credentials falling into nefarious hands.');
            debug('WARNING: This request is not secure. Strict-Transport-Security header has been set.');
            res.set('Strict-Transport-Security', `max-age=${HSTS_HEADER_AGE}`);
        }

        const missing_cookies = COOKIES_NEEDED_FOR_VALIDATION.map(cookieRequired => {

                if(process.env.NODE_ENV === 'development'){
                    debug('Looking for:', cookieRequired);
                    debug('Found: ', req.cookies[cookieRequired]);
                }

                if(!req.cookies[cookieRequired]){
                    return cookieRequired;
                } else {
                    return null;
                }

            })
            .filter(isNullValue => isNullValue !== null)
        ;

        if(missing_cookies.length > 0){
            debug(`Missing cookies required to validate session '${missing_cookies.join(`', '`)}'. Redirecting to login.`);
            res.cookie( 'w3id_redirect', req.originalUrl, { httpOnly : false, maxAge : thirtyMinutesInMilliseconds } );
            res.redirect('/__auth');
        } else if(EXPIRATION_TIME - NOW <= 0){
            
            if(process.env.NODE_ENV === 'development'){
                debug(`Session is too old. Invalidating. EXPIRATION_TIME: ${EXPIRATION_TIME} NOW: ${NOW}`);
            }

            clearCookies(res).redirect('/__auth');

        } else {

            const hashGeneratedFromCookiesAndSecret = generateHashForProperties(  decodeURIComponent( req.cookies['w3id_userid'] ),  decodeURIComponent( req.cookies['w3id_sessionid']),  decodeURIComponent( req.cookies['w3id_expiration'] ) );

            if(process.env.NODE_ENV === 'development'){
                debug(`hashGeneratedFromCookiesAndSecret: ${hashGeneratedFromCookiesAndSecret} session_hash: ${session_hash} eq?: ${hashGeneratedFromCookiesAndSecret === session_hash}`);
            }

            if(hashGeneratedFromCookiesAndSecret !== session_hash){
                debug('Session has been tampered with. Invalidating session.');
                res.cookie( 'w3id_redirect', req.originalUrl, { httpOnly : false, maxAge : thirtyMinutesInMilliseconds } );
                res.redirect('/__auth');
            } else {
                debug('Session is valid. Allowing request to continue.');
                res.clearCookie('w3id_redirect');
                res.locals.w3id_userid = req.cookies['w3id_userid'];
                next();
            }

        }

    }

}

router.get('/__auth', (req, res, next) => {

    sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
        if (err !== null){
            debug('GET /__auth ERROR:', err);
            res.status(500).end();
        } else {
            debug(login_url);
            res.redirect(login_url);
        }
      });

});

router.post('/__auth', bodyParser.json(), bodyParser.urlencoded({ extended: false }), cookieParser(), (req, res, next) => {

    if(process.env.NODE_ENV === 'development'){
        debug('req.body:', req.body);
    }
    
    sp.post_assert(idp, { request_body: { RelayState: req.body.RelayState, SAMLResponse: req.body.SAMLResponse } }, function(err, saml_response) {
        if(err){
            debug('Service provider post_assert error:', err);
            res.status(500);
            res.end();
        } else {

            if(process.env.NODE_ENV === 'development'){
                debug('saml_response:', JSON.stringify(saml_response));
            }
    
            const userID = saml_response.user.name_id;
            const sessionID = saml_response.user.session_index;
            const expiration = saml_response.user.session_not_on_or_after;
    
            const propertyHash = generateHashForProperties(userID, sessionID, expiration);
    
            const timeUntilExpirationInMilliseconds = moment(expiration,  'YYYY-MM-DD HH:mm:ss').diff(moment()) - 1;
    
            if(process.env.NODE_ENV === 'development'){
                debug(`COOKIE EXPS >>> expiration: ${expiration} timeUntilExpirationInMilliseconds: ${timeUntilExpirationInMilliseconds}`);
                debug('userID:', userID);
                debug('sessionID:', sessionID);
                debug('expiration:', expiration);
                debug('Setting hash:', propertyHash);
            }
    
            res.cookie( 'w3id_userid', userID, { httpOnly : false, maxAge : timeUntilExpirationInMilliseconds } );
            res.cookie( 'w3id_sessionid', sessionID, { httpOnly : false, maxAge : timeUntilExpirationInMilliseconds } );
            res.cookie( 'w3id_expiration', expiration, { httpOnly : false, maxAge : timeUntilExpirationInMilliseconds } );
            res.cookie( 'w3id_hash', propertyHash, { httpOnly : false, maxAge : timeUntilExpirationInMilliseconds } );
    
            if(req.cookies['w3id_redirect']){
    
                const redirectTo = req.cookies['w3id_redirect'];
                res.redirect(redirectTo);
    
            } else {
                res.redirect('/');
            }

        }

    });

} );

router.all('*', [ cookieParser() ], validateSession);

module.exports = router;
module.exports.generateHashForProperties = generateHashForProperties;