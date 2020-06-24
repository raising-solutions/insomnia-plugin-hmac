const tag = require('..').templateTags[0];

function assertTemplate(args, expected) {
  return async function() {
    const result = await tag.run(null, ...args);
    expect(result).toBe(expected);
  };
}

function assertTemplateFails(args, expected) {
  return async function() {
    try {
      await tag.run(null, ...args);
      fail(`Render should have thrown ${expected}`);
    } catch (err) {
      expect(err.message).toContain(expected);
    }
  };
}

describe('Plugin', () => {
  
});
