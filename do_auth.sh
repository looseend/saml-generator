#!/bin/zsh

# Use a SAMLResponse to get an auth code and then use that to get a token, using PKCE

SSO_URL=${SSO_URL:-https://sso.8x8pilot.com/}
client_id=${client_id:-vom_8_android}
client_id_64=$(echo -n ${client_id}\: | base64)
subject=${1-smart.test}
issuer=${2-com.smart.alpha}

# Empty the cookie jar
rm -f cookie.txt

# Create the verifier and challenge for PKCE

code_verifier=$(LC_CTYPE=C && LANG=C && cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1)
code_challenge=$(echo -n $code_verifier | shasum -a 256 | cut -d " " -f 1 | xxd -r -p | base64 | tr / _ | tr + - | tr -d =)

echo "SSO: $SSO_URL"
echo "Challenge: $code_challenge"
echo "Verifier: $code_verifier"
echo "Client: $client_id"
echo "Client64: ${client_id_64}"
echo "Subject=${subject}"

# Use the Java app to create the signed SAMLResponse

SAMLResponse=$(java -jar target/saml-generator-1.0.jar -subject ${subject}  -issuer ${issuer} -privateKey smart.pkcs8 -publicKey smart.crt | base64)

# Authenticate using the SAMLResponse
# Note the use of a cookie jar, this maintains the authenticated session so we can get an auth code in the next step

curl --cookie cookie.txt --cookie-jar cookie.txt -s -D - --request POST --url ${SSO_URL}saml2 --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "SAMLResponse=${SAMLResponse}" \
  --data-urlencode "RelayState=target=app://com.android" -o /dev/null

# Get the auth code using the cookie jar to maintain the session
echo "get code"
redirect=$(curl --cookie cookie.txt --cookie-jar cookie.txt -s -S  --request POST --url ${SSO_URL}v2/oauth/authorize \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --header 'Accept: application/json' \
  -w '%header{location}' \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=${client_id}" \
  --data-urlencode "redirect_uri=com.eght.vom://oauth2redirect" \
  --data-urlencode "response_type=code" \
  --data-urlencode "code_challenge=${code_challenge}" \
  --data-urlencode "state=1234" \
  --data-urlencode "code_challenge_method=S256" \
  -o /dev/null)

# Extract the auth code from the redirect URL
auth_code=$(echo ${redirect} | sed -e 's/.*?code=\([^&]*\).*$/\1/g')

echo "get token for code: ${auth_code}"

# Exchange the auth code for a token

curl --cookie cookie.txt --cookie-jar cookie.txt -sS --request POST --url ${SSO_URL}v2/oauth/token \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --header "authorization: Basic ${client_id_64}" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${auth_code}" \
  --data-urlencode "redirect_uri=com.eght.vom://oauth2redirect" \
  --data-urlencode "state=1234" \
  --data-urlencode "code_verifier=${code_verifier}" \
   -o -