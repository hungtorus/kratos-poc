local claims = {
  email_verified: false,
} + std.extVar('claims');

local email = if 'email' in claims && claims.email_verified then claims.email else null;
local username = if email != null then std.split(email, '@')[0] else 'google-' + claims.sub;

{
  identity: {
    traits: {
      username: username,
      [if email != null then 'email' else null]: email,
      [if email != null then 'google_email' else null]: email,
    },
    metadata_public: {
      google_sub: claims.sub,
    },
    verified_addresses: if email != null then [
      { value: email, via: 'email' },
    ] else [],
  },
}
