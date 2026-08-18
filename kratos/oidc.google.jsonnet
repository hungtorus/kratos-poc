local claims = {
  email_verified: false,
} + std.extVar('claims');

{
  identity: {
    traits: {
      [if 'email' in claims && claims.email_verified then 'email' else null]: claims.email,
      [if 'email' in claims && claims.email_verified then 'google_email' else null]: claims.email,
    },
    metadata_public: {
      google_sub: claims.sub,
    },
    verified_addresses: if 'email' in claims && claims.email_verified then [
      { value: claims.email, via: 'email' },
    ] else [],
  },
}
