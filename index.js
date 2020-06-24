const crypto = require('crypto');

module.exports.templateTags = [
  {
    name: 'HMAC',
    displayName: 'HMAC',
    description: 'Generate HMAC hash from content',
    args: [
      {
        displayName: 'Hashing Algorithm',
        type: 'enum',
        options: [
          { displayName: 'MD5', value: 'md5' },
          { displayName: 'SHA1', value: 'sha1' },
          { displayName: 'SHA256', value: 'sha256' },
          { displayName: 'SHA512', value: 'sha512' },
        ],
      },
      {
        displayName: 'Hash Encoding',
        description: 'The encoding of the content hash generated',
        type: 'enum',
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'Base64', value: 'base64' },
        ],
      },
      {
        displayName: 'HMAC Key',
        type: 'string',
        placeholder: 'HMAC key used to generate signature',
      },
      {
        displayName: 'HMAC Key Encoding',
        type: 'enum',
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'Base64', value: 'base64' },
        ],
      },
      {
        displayName: 'HMAC Signature Algorithm',
        type: 'enum',
        options: [
          { displayName: 'MD5', value: 'md5' },
          { displayName: 'SHA1', value: 'sha1' },
          { displayName: 'SHA256', value: 'sha256' },
          { displayName: 'SHA512', value: 'sha512' },
        ],
      },
      {
        displayName: 'HMAC Signature Encoding',
        description: 'The encoding of the output',
        type: 'enum',
        options: [
          { displayName: 'Hexadecimal', value: 'hex' },
          { displayName: 'Base64', value: 'base64' },
        ],
      },// digestPattern, value
      {
        displayName: 'DigestPattern',
        type: 'string',
        defaultValue: '{hash}',
        placeholder: 'Pattern used to make the digest text',
      },
      {
        displayName: 'Content',
        type: 'string',
        placeholder: 'Value to hash (Otherwise body will be used)',
      },
    ],
    run(context, hash_algorithm, hash_encoding, hmac_key, hmac_key_encoding, hmac_signature_algorithm, hmac_signature_encoding, digestPattern, digestPatternvalue = '') {
      const encodedUri = ''; //encodeURIComponent(context.request.getUrl());
      let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

      const valueType = typeof value;
      if (valueType !== 'string') {
        throw new Error(`Cannot hash value of type "${valueType}"`);
      }

      if(digestPattern !== ''){
        throw new Error(`Cannot make the signature with a DigestPattern value of "${digestPattern}"`);
      }

      value = value || context.request.getBodyText() || '';

      if(value !== ''){
        const hash_builder = crypto.createHash(hash_algorithm);
        hash_builder.update(value, 'utf8');
        hash = hash_builder.digest(hash_encoding);
      }

      const digest = digestPattern.toLowerCase()
          .replace(/{encodedUri}/g, encodedUri)
          .replace(/{hash}/g, hash);
          //.split('{hash}').join(hash);

      //(apiKey + nonce + timeStamp + config.method + encodeURIComponent(config.url) + dataHash).toLowerCase();

      var hmacBuilder = new jsSHA(hmac_signature_algorithm, "utf8");
      hmacBuilder.setHMACKey(hmac_key, hmac_key_encoding);
      hmacBuilder.update(digest);
      return hmacBuilder.getHMAC(hmac_signature_encoding);
    },
  },
];
