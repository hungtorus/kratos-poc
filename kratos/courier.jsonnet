function(ctx) {
  recipient: ctx.recipient,
  subject: ctx.subject,
  body: ctx.body,
  html_body: if 'html_body' in ctx then ctx.html_body else null,
  template_type: ctx.template_type,
  login_code: if 'template_data' in ctx && 'login_code' in ctx.template_data then ctx.template_data.login_code else null,
  registration_code: if 'template_data' in ctx && 'registration_code' in ctx.template_data then ctx.template_data.registration_code else null,
  verification_code: if 'template_data' in ctx && 'verification_code' in ctx.template_data then ctx.template_data.verification_code else null,
  recovery_code: if 'template_data' in ctx && 'recovery_code' in ctx.template_data then ctx.template_data.recovery_code else null,
  template_data: if 'template_data' in ctx then ctx.template_data else null,
}
