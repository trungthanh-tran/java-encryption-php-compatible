# Generate the encrypted text by using AES-CBC-128 in java then decrypt in laravel using https://laravel.com/api/6.x/Illuminate/Support/Facades/Crypt.html
# Key is base64 from .env in laravel.
# Input
## Plain text to encrypt
## Key in base 64
# Output
## Base64 with {"iv":"iv_here", "value": "encrypted_text", "mac":"mac"}
### mac is hmacsha256(iv+value, key in env).
