Package.describe({
  name         : 'weihai:accounts-rest',
  version      : '0.0.1',
  summary      : 'A rest login service based on mobile phone number, forked from simple-rest:account-password.',
  documentation: null
});

Package.onUse(function (api) {
  api.versionsFrom('1.1.0.2');

  api.use([
    'weihai:accounts-phone',
    'check',
    'simple:json-routes@2.1.0',
    'simple:authenticate-user-by-token@1.0.1',
    'simple:rest-bearer-token-parser@1.0.1',
    'simple:rest-json-error-handler@1.0.1',
    'underscore',
  ], 'server');

  api.addFiles('rest-phone-login.js', 'server');
});