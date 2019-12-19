# README

Adds REST authentation to Meteor.

## Login
```
HTTP.post('/users/login', {
  user: {
    phone: 'phonenumber', // or 'email'   
  },
  password: { // or plain text string
    digest: '*',
    algorithm: 'sha-256
  }
})
```

If successfuly, the above request will return an object:

```
{
  id: 'userid',
  token: 'user_token',
  tokenExpires: date
}
```

In subsequent request, add the token to authenticate the user.

Accepts tokens passed via the standard header or URL query parameter (whichever is found first, in that order).

The header signature is: Authorization: Bearer <token>

The query signature is: ?access_token=<token>

## Register
```
HTTP.post('/users/code', {
  "phone": "*",
  "profile": {
    "name": "<username>"
  }
})
```

Returns, and sends verification code.
```
{
  "userId": "<userid>"
}
```

## Send verification code to phone
```
HTTP.post({
  "phone": "*"
})
```

Empty response if successfuly.

## Reset password
```
HTTP.post('/users/reset', {
  phone: 'phonenumber',
  code: '*',
  password: { // or plain text string
    digest: '*',
    algorithm: 'sha-256'
  }
})
```

Response:
```
{
  id: 'userid',
  token: 'user_token',
  tokenExpires: date
}
```

## Cookie
We may want to use cookie on the client to store login token to enable multi-site login.