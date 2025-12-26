# Visa Postman Encryption Lib
Library for encrypting visa api requests in postman

## Usage
In postman :

 - Copy the contents of the [minified bundle](#build-the-minified-bundle-file) as an environment variable `encryptionScript` .
- Set the required environment variables for encryption
- Set this as a pre-request script:
```
    eval(pm.environment.get("encryptionScript"));
    encryptRequest(pm); 
```
- Run the request.

## Development
##### Requires
    Node 18+
    npm 9+

##### Build the minified bundle file

    npm run minify

The output will be created in the `dist/` directory.

