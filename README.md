# Image Folder (password + authenticator-app MFA)

Run `node server.js` (Node 18+, no npm install needed), then open http://localhost:3000

1. **Create account** -> scan the QR (or type the key) in Google/Microsoft Authenticator or Authy -> enter the 6-digit code.
2. Later logins: username + password -> 6-digit code -> your image folder.
3. Upload by drag-and-drop or click; **Log out** is at the bottom.

Security notes: scrypt password hashing, RFC 6238 TOTP (+/-30 s, replay-blocked), 5-attempt lockouts,
HttpOnly/SameSite=Strict sessions, images only served to their owner, type checked by file signature.
For production put it behind HTTPS and set COOKIE_SECURE=1. Data lives in ./data.
