// Enable cross origin requests for all endpoints
JsonRoutes.setResponseHeaders({
  "Cache-Control": "no-store",
  "Pragma": "no-cache",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, PUT, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With"
});

JsonRoutes.Middleware.use(JsonRoutes.Middleware.parseBearerToken);
JsonRoutes.Middleware.use(JsonRoutes.Middleware.authenticateMeteorUserByToken);

// Handle errors specifically for the login routes correctly
JsonRoutes.ErrorMiddleware.use('/users/login', RestMiddleware.handleErrorAsJson);
JsonRoutes.ErrorMiddleware.use('/users/register', RestMiddleware.handleErrorAsJson);

JsonRoutes.add('options', '/users/login', function (req, res) {
  JsonRoutes.sendResult(res);
});

// Request body must be json object:
// @property {Object} user - with one and only one of the following identifier
//    -phone, email, (id or phoneAndEmail)
// @property {Object|string} password - plain password string or hashed object:
//    - {string} digest - hashed password string
//    - {string} algirithm - 'sha-256'
JsonRoutes.add('post', '/users/login', function (req, res) {
  
  var options = req.body;

  var result = Accounts._loginWithPhoneAndEmail(options);

  check(result, {
    userId: String,
    error: Match.Optional(Meteor.Error),
  });

  if (result.error) {
    throw result.error;
  }

  var stampedLoginToken = Accounts._generateStampedLoginToken();
  check(stampedLoginToken, {
    token: String,
    when: Date,
  });

  Accounts._insertLoginToken(result.userId, stampedLoginToken);

  var tokenExpiration = Accounts._tokenExpiration(stampedLoginToken.when);
  check(tokenExpiration, Date);

  JsonRoutes.sendResult(res, {
    data: {
      id: result.userId,
      token: stampedLoginToken.token,
      tokenExpires: tokenExpiration,
    },
  });

});

JsonRoutes.add('options', '/users/register', function (req, res) {
  JsonRoutes.sendResult(res);
});

JsonRoutes.add('post', '/users/register', function (req, res) {
  if(Accounts._options.forbidClientAccountCreation) {
    JsonRoutes.sendResult(res, {code: 403});
  } else {
    var options = req.body;

    check(options, {
      username: Match.Optional(String),
      email: Match.Optional(String),
      password: String,
    });

    var userId = Accounts.createUser(
      _.pick(options, 'username', 'email', 'password'));

    // Log in the new user and send back a token
    var stampedLoginToken = Accounts._generateStampedLoginToken();
    check(stampedLoginToken, {
      token: String,
      when: Date,
    });

    // This adds the token to the user
    Accounts._insertLoginToken(userId, stampedLoginToken);

    var tokenExpiration = Accounts._tokenExpiration(stampedLoginToken.when);
    check(tokenExpiration, Date);

    // Return the same things the login method returns
    JsonRoutes.sendResult(res, {
      data: {
        token: stampedLoginToken.token,
        tokenExpires: tokenExpiration,
        id: userId,
      },
    });
  }
});