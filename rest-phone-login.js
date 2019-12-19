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
// JsonRoutes.ErrorMiddleware.use('/users/login', RestMiddleware.handleErrorAsJson);
// JsonRoutes.ErrorMiddleware.use('/users/register', RestMiddleware.handleErrorAsJson);
// JsonRoutes.ErrorMiddleware.use('/users/reset', RestMiddleware.handleErrorAsJson);
JsonRoutes.ErrorMiddleware.use(RestMiddleware.handleErrorAsJson);


//=====================================
//              Login
// ====================================

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

  var data = _createLoginToken(result.userId)

  JsonRoutes.sendResult(res, { data });

});


//=====================================
//             Register
// ====================================

JsonRoutes.add('options', '/users/register', function (req, res) {
  JsonRoutes.sendResult(res);
});

JsonRoutes.add('post', '/users/register', function (req, res) {
    var options = req.body;
    var data = {};

    check(options.phone, String);
    options.phone = Accounts.normalizePhone(options.phone);
    // console.log(options)
    var userId = Accounts.createUserWithPhone(options);
    if (!userId)
      throw new Error("createUser failed to insert new user");
    data.userId = userId;

    // Send verification code
    if (Accounts._options.sendPhoneVerificationCodeOnCreation) {
      Accounts.sendPhoneVerificationCode(userId, options.phone, 'create');
      data.codeSend = true;
    }

    // Return the same things the login method returns
    JsonRoutes.sendResult(res, { data });
});

// JsonRoutes.add('post', '/users/register', function (req, res) {
//   if(Accounts._options.forbidClientAccountCreation) {
//     JsonRoutes.sendResult(res, {code: 403});
//   } else {
//     var options = req.body;

//     check(options, {
//       username: Match.Optional(String),
//       email: Match.Optional(String),
//       password: String,
//     });

//     var userId = Accounts.createUser(
//       _.pick(options, 'username', 'email', 'password'));

//     // Log in the new user and send back a token
//     var stampedLoginToken = Accounts._generateStampedLoginToken();
//     check(stampedLoginToken, {
//       token: String,
//       when: Date,
//     });

//     // This adds the token to the user
//     Accounts._insertLoginToken(userId, stampedLoginToken);

//     var tokenExpiration = Accounts._tokenExpiration(stampedLoginToken.when);
//     check(tokenExpiration, Date);

//     // Return the same things the login method returns
//     JsonRoutes.sendResult(res, {
//       data: {
//         token: stampedLoginToken.token,
//         tokenExpires: tokenExpiration,
//         id: userId,
//       },
//     });
//   }
// });

//=====================================
//         Verification code
// ====================================

JsonRoutes.add('options', '/users/code', function (req, res) {
  JsonRoutes.sendResult(res);
});

// Sends verification code
// @property {String} req.phone
JsonRoutes.add('post', '/users/code', function (req, res) {
  var options = req.body;
  check(options.phone, String);

  var phone = Accounts.normalizePhone(options.phone);
  if (!phone)
    throw new Meteor.Error(400, "not.valid.phone");

  // Get user by phone
  var user = Meteor.users.findOne({ 'phone.number': phone }, {fields: {'_id': 1}});
  if (!user)
    throw new Meteor.Error(400, 'not.valid.phone')

  try {
    Accounts.sendPhoneVerificationCode(user._id, phone, 'reset');
  }
  catch(e) {
    throw new Meteor.Error(500, e.message)
  }

  JsonRoutes.sendResult(res, {});
});

//=====================================
//             Reset
// ====================================

// Sets new password.
JsonRoutes.add('options', '/users/reset', function (req, res) {
  JsonRoutes.sendResult(res);
});

//
// req.body = {
//   id: 'phone',
//   code: 'code',
//   password: 'password'
// }
//
JsonRoutes.add('post', '/users/reset', function (req, res) {
  var options = req.body;
  var data = {};

  check(options, {
    phone: String,
    code: String,
    password: passwordValidator
  });

  var phone = Accounts.normalizePhone(options.phone);
  if (!phone)
    throw new Meteor.Error(403, "not.valid.phone");
  var user = Meteor.users.findOne({
    "phone.number": phone
  });
  // console.log('user:', user)
  if (!user)
      throw new Meteor.Error(403, "Not a valid phone");

  // Verify code is accepted
  if (
    !user.services.phone 
    || !user.services.phone.verify 
    || !user.services.phone.verify.code 
    || user.services.phone.verify.code != options.code
  ) {
    //console.log('not valid');
    throw new Meteor.Error(403, "Not a valid code");
  }

  // Now we can  reset password and login user
  
  var setOptions = {'phone.verified': true},
      unSetOptions = {'services.phone.verify': 1};

  var hashed = Accounts._hashPassword(options.password);

  setOptions['services.phone.bcrypt'] = hashed;
  unSetOptions['services.phone.srp'] = 1;

  var query = {
      _id                         : user._id,
      'phone.number'              : phone,
      'services.phone.verify.code': options.code // we don't really need this but used as safe gaurd.
  };

  // Update the user record by:
  // - Changing the password to the new one
  // - Forgetting about the verification code that was just used
  // - Verifying the phone, since they got the code via sms to phone.
  var affectedRecords = Meteor.users.update(query,
  {
    $set: setOptions,
    $unset: unSetOptions
  });

  if (affectedRecords !== 1)
    throw new Meteor.Error(403, "Invalid phone")

  // successfulVerification(user._id);

  // Replace all valid login tokens with new ones (changing
  // password should invalidate existing sessions).
  Accounts._clearAllLoginTokens(user._id);

  data = _createLoginToken(user._id);

  // Return the same things the login method returns
  JsonRoutes.sendResult(res, {
    data
  });
});

/**
 * Creates login token
 * @param {*} result 
 */
function _createLoginToken(userId) {
  var stampedLoginToken = Accounts._generateStampedLoginToken();
  check(stampedLoginToken, {
    token: String,
    when: Date,
  });

  Accounts._insertLoginToken(userId, stampedLoginToken);

  var tokenExpiration = Accounts._tokenExpiration(stampedLoginToken.when);
  check(tokenExpiration, Date);

  return {
    id: userId,
    token: stampedLoginToken.token,
    tokenExpires: tokenExpiration,
  };
}

var passwordValidator = Match.OneOf(
  String,
  { digest: String, algorithm: String }
);