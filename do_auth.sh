#!/bin/sh

SAMLResponse=$(java -jar target/saml-generator-1.0.jar -subject smart.test  -issuer com.smart.alpha -privateKey smart.pkcs8 -publicKey smart.crt | base64)

curl -sS -D - --request POST --url https://sso.8x8pilot.com/saml2 --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=${SAMLResponse}" \
  --data-urlencode "RelayState=target=app://com.android" -o /dev/null

