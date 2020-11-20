# W3ID-Middleware

Middleware for servers running Express.js to secure routes with W3ID

Installation:

```bash
$ npm i git://github.com/hendriku/w3id-middleware#0.3.0
$ yarn add git://github.com/hendriku/w3id-middleware#0.3.0
```

## Description

This middleware uses W3ID to authenticate users of an Express service. Once a users identity has been validated, a session is created for the user that enable them to access routes for the duration of that session.

These details for the sessions are stored in the cookies of the client.

## Features

-   Horizontally Scalable

    -   Sessions are created and validated using a shared secret key stored in the environment variables of the application. Each server with this key should be able to validate the authenticity of the session

-   Easy to use

    -   Two lines of code, secure your application.

-   Redirect support

    -   When the authentication flow has been completed, the user ends up where they wanted to be, not some arbitrary route.

-   Invalidation support

    -   The application developer can choose to invalidate a session and challenge the user to reauthenticate at any time.

-   Configurable Route Protection
    -   Every route can be protected, or only some - it's up to you!

## Rationale

#### Practicality

I've written this middleware so as to enable IBMers to have the freedom to experiment with new ideas and services without the fear that it will become available to the general public before it's ready.

Developers shouldn't have to spend time thinking about their security strategy, they should be writing and testing their applications. I hope that this middleware serves that purpose.

#### Cost / time Saving

Most of the Node.js projects I've seen with a Passport SAML integration have either used an in-memory session store (which forces services to scale vertically, or create sticky sessions across application instances) or run a database instance to manage the session (which might be rarely used, and has an associated cost).

By using cookies, and having a shared secret across application instances, services can scale horizontally (so if the thing you're testing gets a wider audience, there's no need to rearchitect your solution, just remove the middleware), and there's no need for you to run a database.

## Usage

Before you can use the W3ID middleware in your application, you will need to register your application with the W3ID self-service systems to create the nesseccary prerequisites. You can find instructions to do so [here](SELF_SERVICE.md) (see the [Notes and Catch-22s](#notes-and-catch-22s) section in this document for details on considerations you'll have to make whilst registering your app). Once you have done so, you can secure your application using the following steps.

1. Install the module, and save it as a dependency

    ```
    npm i -S w3id-middleware
    ```

2. Require the module in your Express application

    ```JavaScript
    const w3id = require('w3id-middleware');
    ```

3. Either:

    - Secure all of the routes in your application:

    ```JavaScript
    const w3id = require('w3id-middleware');
    app.use(w3id);
    ```

    - Secure some of the routes in your application:

    ```JavaScript
    const w3id = require('w3id-middleware');

    app.get('/', require('routes/index')); // Publically accessible routes
    app.get('/protected', w3id, require('routes/protected')); // Routes that require W3ID authentication
    app.get('/unprotected', require('routes/unprotected')); // More publically accessible routes
    app.use(w3id); // All routes defined after this point will be protected by the middleware.
    app.get('/everything-else', require('routes/everything-else')); // Like this!
    ```

4. Relax.

## The Authentication Process

This middleware uses the SAML authentication flow with the W3ID service acting as an identity provider, and this middleware augmenting your application to act as a service provider.

## The Validation flow

When a client tries to access an endpoint that has been secured by the w3id-middleware module, the following steps will occur.

1. The middleware will check for the `w3id_challenge` cookie.
    - If set, any details for an existing session will be invalidated, and the user will be redirected to their intended URL. If not, the validation process will continue.
2. The middleware will check for the `w3id_hash` cookie.
    - If not set, the `w3id_redirect` cookie will be set to the route that the user was trying to access, and they will be redirected to the `/__auth` path instead.
    - If set, the validation process will continue
3. The middleware next checks whether all of the cookies required to validate the session are present. At this point in the flow there should be at least:
    1. w3id_userid
    2. w3id_sessionid
    3. w3id_expiration
    4. w3id_hash
4. If one or more of the required cookies are missing, then the `w3id_redirect` cookie will be set with the path the user was trying to reach, and then the user will be redirected to the `__/auth` path. If all of the cookies required for validation are present the sessions will next be evaluated.
5. An MD5 hash will be generated from the concatenated the `w3id_userid`, `w3id_sessionid`, `w3id_expiration`, and `W3ID_SECRET` environment variable (joined with a `-`). If this hash does not equal the hash stored in the `w3id_hash` cookie, the session is considered to have been tampered with and will be invalidated. The `w3id_redirect` cookie will be set to the route that the user was trying to access, and they will be redirected to the `/__auth` path. If the hash generated is equal to the hash stored in the `w3id_hash` cookie, then we consider the session valid and will allow the user to proceed to their desired route.

## Invalidating a session

If you wish to force a user to reauthenticate with W3ID, you can set the `w3id_challenge` flag to `1`. The next time a request is made by the client, the `w3id_<NAME>` cookies for the existing session will be cleared and the validation / authentication processes will be triggered.

## Notes and Catch-22s

A. The middleware requires the `/__auth` (**that's two underscores**) for both the `GET` and `POST` HTTP verbs. If you need to handle traffic on these endpoints, you will not be able to use those routes and this middleware at the same time.

B. This middleware will not force connections to use HTTPS, but will warn whenever it detects that a connection is insecure. Take care to secure your services, otherwise valid credentials may fall into the hands of malicious actors, and you won't be able to invalidate them until the original expiration time of the session (up to 24 hours).

C. If the middleware detects at any point that HTTP requests are being made to the server, it will not enforce HTTPS, but it will warn that this is not recommended and set a `Strict-Transport-Security` header. This will not force the user to use HTTPS, however, any browser that respects this header will keep using HTTPS if it is used once for any route by the client.

D. When entering the ACS URL as you register your application with W3ID, it must point to the path `/__auth` of your application. For example, if your service is at `https://awsome-thing-i-made.com`, your ACS URL needs to be `https://awsome-thing-i-made.com/__auth` in order for the middleware to successfully complete the authentication process.

## Registering an app with the W3ID self-service application.

[Diego Hernandez](https://twitter.com/diego_codes) has written an excellent guide to setting yourself up with the W3ID service (his demo application was the basis for my creation of this middleware).

A slightly ammended version of the instructions can be found in [SELF_SERVICE.md](SELF_SERVICE.md).

If you have access to IBM's Enterprise GH account, you can find the original the [IBM Enterprise Github](https://github.ibm.com/Diego-Hernandez/w3-sso-node-passport#provision-application-ibm-sso-service).

## Required Environment Variables

`W3ID_IDP_LOGIN_URL`

The W3ID login URL generated by the W3ID self-service application. This is the URL that your user will be initially redirected to to provide proof of their identity through W3ID.

`W3ID_PARTNER_ID`

The unique partner ID you created for you app in the W3ID self-service application.

`W3ID_CERT`

The _content_ of the `<X509Certificate>` element from the XML document generated at the end of the W3ID self-service application - _not the entire element_. The middleware will handle the creation of the certificate headers and footers, so don't do those yourself.

`W3ID_SECRET`

A customisable secret to be shared between the instances of the application. This value is used to generate the hash that the middleware uses to detect tampering with the session values. **It must be at least 72 characters long**.

## Optional Environment Variables

`NODE_ENV`

If set to `development` the authorisation flow will be verbose. **This means logging out valid authentication information to the user** _do not use this in a production environment, lest you fall victim to a MITM attack!_

## res.locals

For convenience, the name_id (primary email) and the attributes of the IBM employee are accessible server side in `res.locals.w3id_name_id`, `res.locals.w3id_attributes`, `w3id_blueGroups`.

The attributes are structured as the following:

```
	"firstName": ["Max"],
	"uid": ["123456789"],
	"lastName": ["Musterman"],
	"emailaddress": ["Max.Musterman@ibm.com"],
	"cn": ["Max M Musterman"]
```

If you access them (especially from the frontend) you'll have to use:

```
JSON.parse(decodeURIComponent(cookie.your_field))
```

To get machine readable data.
