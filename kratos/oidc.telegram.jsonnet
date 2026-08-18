local claims = std.extVar('claims');
local raw = if 'raw_claims' in claims then claims.raw_claims else {};
// Official Telegram OIDC id_token claims (https://core.telegram.org/bots/telegram-login)
local tid = std.get(raw, 'id', std.get(raw, 'sub', claims.sub));
local username = std.get(raw, 'preferred_username', null);

{
  identity: {
    traits: {
      email: std.asciiLower('telegram-' + std.toString(tid) + '@telegram.local'),
      telegram_id: std.toString(tid),
      [if username != null then 'telegram_username' else null]: username,
    },
    metadata_public: {
      telegram_id: std.toString(tid),
      [if username != null then 'telegram_username' else null]: username,
    },
  },
}
