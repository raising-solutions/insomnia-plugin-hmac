const crypto = require('crypto');
const jsSHA = require('./jsSHA');


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
          { displayName: 'SHA-1', value: 'SHA-1' },
          { displayName: 'SHA-256', value: 'SHA-256' },
          { displayName: 'SHA-512', value: 'SHA-512' },
        ],
      },
      {
        displayName: 'Hash Encoding',
        description: 'The encoding of the content hash generated',
        type: 'enum',
        options: [
          { displayName: 'Base64', value: 'B64' },
          { displayName: 'TEXT', value: 'TEXT' },
          { displayName: 'Hexadecimal', value: 'HEX' },
        ],
      },
      {
        displayName: 'HMAC Key',
        type: 'string',
        placeholder: 'HMAC key used to generate signature',
      },
      {
        displayName: 'HMAC Key Type',
        type: 'enum',
        options: [
          { displayName: 'Base64', value: 'B64' },
          { displayName: 'TEXT', value: 'TEXT' },
          { displayName: 'Hexadecimal', value: 'HEX' },
        ],
      },
      {
        displayName: 'HMAC Signature Algorithm',
        type: 'enum',
        options: [
          { displayName: 'SHA-1', value: 'SHA-1' },
          { displayName: 'SHA-256', value: 'SHA-256' },
          { displayName: 'SHA-512', value: 'SHA-512' },
        ],
      },
      {
        displayName: 'HMAC Signature Encoding',
        description: 'The encoding of the output',
        type: 'enum',
        options: [
          { displayName: 'Base64', value: 'B64' },
          { displayName: 'Hexadecimal', value: 'HEX' },
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
    run(context, hash_algorithm, hash_encoding, hmac_key, hmac_key_encoding, hmac_signature_algorithm, hmac_signature_encoding, digestPattern, content = '') {
      const encodedUri = ''; //encodeURIComponent(context.request.getUrl());
      let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

      console.log('content', `"${content}"`);

      const contentType = typeof content;
      if (contentType !== 'string') {
        throw new Error(`Cannot hash content of type "${contentType}"`);
      }

      if(digestPattern === ''){
        throw new Error(`DigestPattern is not defined`);
      }

      console.log('content before', `"${content}"`);
      content = content || ''; // context.request.getBodyText() || '';
      console.log('content after', `"${content}"`);

      if(content !== ''){
        // const hash_builder = crypto.createHash(hash_algorithm);
        // hash_builder.update(content, 'utf8');
        // hash = hash_builder.digest(hash_encoding);
        var shaObj = new jsSHA(hash_algorithm, "TEXT");
        shaObj.update(content);
        hash = shaObj.getHash(hash_encoding);
      }

      console.log('hash', hash);
      console.log('digestPattern', digestPattern);

      const digest = encodeURIComponent(digestPattern
          .replace(/{encodedUri}/g, encodedUri)
          .replace(/{hash}/g, hash)).toLowerCase();
          //.split('{hash}').join(hash);

      console.log('digest', digest);
      //(apiKey + nonce + timeStamp + config.method + encodeURIComponent(config.url) + dataHash).toLowerCase();

      // var hmacBuilder = crypto.createHmac(hmac_signature_algorithm, hmac_key, {decodeStrings: true, encoding: hmac_key_encoding});
      // hmacBuilder.update(digest, 'utf8');
      // const signature = hmacBuilder.digest(hmac_signature_encoding);
      const hmacObj = new jsSHA(hmac_signature_algorithm, "TEXT");
      hmacObj.setHMACKey(hmac_key, hmac_key_encoding);
      hmacObj.update(digest);
      const signature = hmacObj.getHMAC(hmac_signature_encoding);

      console.log('signature', signature);
      return signature;
      // hmacBuilder.setHMACKey(hmac_key, hmac_key_encoding);
    },
  },
];
