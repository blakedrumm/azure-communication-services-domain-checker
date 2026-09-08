# ===== Browser-only SMTP response lookup =====
# Kept outside #results so partial DNS renders cannot discard the open dialog.
# Only request-time CSP tokens may be used after 20f-HtmlPostProcess.ps1.
$htmlPage += @'
<style nonce="__CSP_NONCE__">
.smtp-tool-band {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 20px;
  padding: 16px 0;
  border-top: 1px solid var(--border);
}
.smtp-tool-band h2 { margin: 0; font-size: 16px; }
.smtp-tool-button, .smtp-icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 36px;
  margin: 0;
  padding: 8px 12px;
  border: 1px solid var(--button-border-secondary);
  border-radius: 4px;
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  font: inherit;
  font-size: 13px;
  line-height: 1.4;
  cursor: pointer;
  max-width: 100%;
}
.smtp-tool-button span { min-width: 0; overflow-wrap: anywhere; }
.smtp-tool-button:hover, .smtp-icon-button:hover:not(:disabled) { background: var(--border); }
.smtp-tool-button:focus-visible, .smtp-icon-button:focus-visible,
.smtp-dialog input:focus-visible, .smtp-dialog textarea:focus-visible,
.smtp-dialog select:focus-visible, .smtp-table-wrap:focus-visible {
  outline: 2px solid var(--button-bg);
  outline-offset: 2px;
}
.smtp-icon-button { width: 36px; height: 36px; padding: 8px; flex: 0 0 36px; }
.smtp-icon-button:disabled { opacity: 0.45; cursor: not-allowed; }
.smtp-tool-icon { width: 16px; height: 16px; flex: 0 0 16px; }
.dark .smtp-tool-icon { filter: invert(1); }
.smtp-dialog {
  width: min(1100px, calc(100% - 24px));
  max-width: calc(100% - 24px);
  max-height: calc(100% - 24px);
  margin: auto;
  padding: 0;
  border: 1px solid var(--input-border);
  border-radius: 8px;
  background: var(--card-bg);
  color: var(--fg);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
  overflow: hidden;
  letter-spacing: 0;
}
.smtp-dialog[open] { display: flex; flex-direction: column; }
.smtp-dialog::backdrop { background: rgba(0, 0, 0, 0.55); }
.smtp-dialog [hidden] { display: none !important; }
.smtp-dialog-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  flex: 0 0 auto;
}
.smtp-dialog-header h2 { margin: 0; font-size: 18px; line-height: 1.4; min-width: 0; overflow-wrap: anywhere; }
.smtp-dialog-body { padding: 16px 20px 20px; overflow-y: auto; min-height: 0; }
.smtp-modes { display: flex; width: fit-content; max-width: 100%; margin: 0 0 16px; padding: 0; border: 0; }
.smtp-modes label { position: relative; display: flex; flex: 1 1 0; min-width: 0; cursor: pointer; }
.smtp-modes span {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 8px 14px;
  min-height: 36px;
  width: 100%;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  font-size: 13px;
  text-align: center;
  overflow-wrap: anywhere;
}
.smtp-modes input:checked + span { background: var(--button-bg); color: var(--button-fg); border-color: var(--button-bg); }
.smtp-modes input:focus-visible + span { outline: 2px solid var(--button-bg); outline-offset: 2px; }
.smtp-input-label { display: block; margin-bottom: 6px; font-size: 13px; font-weight: 600; }
.smtp-dialog textarea, .smtp-dialog input[type="search"], .smtp-dialog select {
  display: block;
  width: 100%;
  min-width: 0;
  margin: 0;
  padding: 9px 10px;
  border: 1px solid var(--input-border);
  border-radius: 4px;
  background: var(--card-bg);
  color: var(--fg);
  font: inherit;
  font-size: 14px;
}
.smtp-dialog textarea {
  min-height: 84px;
  max-height: 200px;
  resize: vertical;
  font-family: Consolas, 'Courier New', monospace;
  line-height: 1.5;
}
.smtp-dialog textarea::placeholder { color: var(--status); opacity: 1; }
.smtp-input-actions, .smtp-output-heading { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
.smtp-reference-filters { display: grid; grid-template-columns: minmax(0, 1fr) minmax(150px, 210px); gap: 12px; }
.smtp-reference-filters > div { min-width: 0; }
.smtp-output-heading { justify-content: space-between; margin: 18px 0 10px; }
.smtp-output-heading h3 { font-size: 14px; margin: 0; }
.smtp-output-status { flex: 1 1 160px; font-size: 12px; color: var(--status); }
.smtp-table-wrap { overflow: auto; max-height: 420px; max-width: 100%; border: 1px solid var(--border); }
.smtp-response-table { width: 100%; min-width: 900px; border-collapse: collapse; table-layout: fixed; font-size: 13px; line-height: 1.5; }
.smtp-response-table th, .smtp-response-table td { padding: 12px; text-align: start; vertical-align: top; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
.smtp-response-table th { position: sticky; top: 0; z-index: 1; background: var(--bg); font-size: 12px; }
.smtp-response-table th:nth-child(1) { width: 72px; }
.smtp-response-table th:nth-child(2) { width: 110px; }
.smtp-response-table th:nth-child(3) { width: 25%; }
.smtp-response-table th:nth-child(4) { width: 25%; }
.smtp-response-table tr:last-child td { border-bottom: 0; }
.smtp-code-cell code { font-family: Consolas, 'Courier New', monospace; font-size: 14px; font-weight: 700; white-space: nowrap; }
.smtp-response-table .tag { display: inline-block; margin-bottom: 6px; white-space: normal; }
.smtp-meaning { display: block; margin-bottom: 6px; }
.smtp-basic-meaning, .smtp-source, .smtp-muted { display: block; color: var(--status); font-size: 12px; }
.smtp-source { margin-top: 6px; }
.smtp-dialog a { color: var(--button-bg); text-underline-offset: 2px; }
.dark .smtp-dialog a { color: #93c5fd; }
.smtp-advice { margin: 8px 0 0; padding-top: 8px; border-top: 1px solid var(--border); }
.smtp-reference-notice { color: var(--status); font-size: 12px; line-height: 1.5; margin: 12px 0 0; }
.smtp-empty { margin: 0; padding: 18px 0; color: var(--status); font-size: 14px; }
.smtp-limit-notice { font-size: 13px; line-height: 1.5; margin: 10px 0 0; }
html.smtp-dialog-open { overflow-y: hidden; }
@media (max-width: 600px) {
  .smtp-dialog-header { padding: 12px; }
  .smtp-dialog-body { padding: 12px; }
  .smtp-dialog-header h2 { font-size: 16px; }
  .smtp-reference-filters { grid-template-columns: minmax(0, 1fr); }
  .smtp-modes { width: 100%; }
  .smtp-table-wrap { max-height: 350px; }
}
</style>

<dialog id="smtpResponseDialog" class="smtp-dialog hide-on-screenshot" aria-labelledby="smtpResponseDialogTitle" aria-describedby="smtpResponseNotice">
  <div class="smtp-dialog-header">
    <h2 id="smtpResponseDialogTitle" data-smtp-i18n="smtpLookupTitle">SMTP &amp; Enhanced SMTP Responses</h2>
    <button type="button" id="smtpResponseClose" class="smtp-icon-button" data-smtp-title="smtpClose" aria-label="Close SMTP response lookup" title="Close SMTP response lookup">
      <img data-smtp-icon="x" class="smtp-tool-icon" alt="" aria-hidden="true" width="16" height="16" />
    </button>
  </div>
  <div class="smtp-dialog-body">
    <fieldset class="smtp-modes">
      <legend class="sr-only" data-smtp-i18n="smtpModeLabel">Response view</legend>
      <label><input class="sr-only" type="radio" name="smtpResponseMode" value="lookup" checked /><span data-smtp-i18n="smtpModeLookup">Response lookup</span></label>
      <label><input class="sr-only" type="radio" name="smtpResponseMode" value="reference" /><span data-smtp-i18n="smtpModeReference">Code reference</span></label>
    </fieldset>
    <form id="smtpResponseForm">
      <label class="smtp-input-label" for="smtpResponseInput" data-smtp-i18n="smtpInputLabel">SMTP response or delivery report</label>
      <textarea id="smtpResponseInput" rows="3" maxlength="16000" spellcheck="false" autocomplete="off" autocapitalize="off" dir="ltr" placeholder="550 5.1.1 Recipient not found"></textarea>
      <div class="smtp-input-actions">
        <button type="submit" class="smtp-tool-button"><img data-smtp-icon="search" class="smtp-tool-icon" alt="" aria-hidden="true" width="16" height="16" /><span data-smtp-i18n="smtpAnalyze">Analyze</span></button>
        <button type="button" id="smtpResponseClear" class="smtp-icon-button" data-smtp-title="smtpClear" aria-label="Clear response" title="Clear response"><img data-smtp-icon="trash-2" class="smtp-tool-icon" alt="" aria-hidden="true" width="16" height="16" /></button>
      </div>
    </form>
    <div id="smtpReferenceFilters" class="smtp-reference-filters" hidden>
      <div><label class="smtp-input-label" for="smtpReferenceSearch" data-smtp-i18n="smtpReferenceSearch">Search codes and meanings</label><input type="search" id="smtpReferenceSearch" maxlength="160" autocomplete="off" /></div>
      <div><label class="smtp-input-label" for="smtpReferenceStatus" data-smtp-i18n="smtpFilterStatus">Status class</label>
        <select id="smtpReferenceStatus">
          <option value="" data-smtp-i18n="smtpAllStatuses">All statuses</option>
          <option value="2" data-smtp-i18n="smtpStatusSuccess">Success</option>
          <option value="3" data-smtp-i18n="smtpStatusContinue">Continue</option>
          <option value="4" data-smtp-i18n="smtpStatusTemporary">Temporary failure</option>
          <option value="5" data-smtp-i18n="smtpStatusPermanent">Permanent failure</option>
        </select>
      </div>
    </div>
    <p id="smtpResponseLimit" class="smtp-limit-notice" role="status" hidden data-smtp-i18n="smtpInputTruncated"></p>
    <div class="smtp-output-heading">
      <h3 id="smtpResponseTableTitle"></h3>
      <span id="smtpResponseStatus" class="smtp-output-status" role="status" aria-live="polite" aria-atomic="true"></span>
      <button type="button" id="smtpResponseCopy" class="smtp-icon-button" data-smtp-title="smtpCopy" aria-label="Copy table" title="Copy table" disabled><img data-smtp-icon="copy" class="smtp-tool-icon" alt="" aria-hidden="true" width="16" height="16" /></button>
    </div>
    <p id="smtpResponseEmpty" class="smtp-empty" hidden></p>
    <div id="smtpResponseTableWrap" class="smtp-table-wrap" tabindex="0" role="region" aria-labelledby="smtpResponseTableTitle">
      <table class="smtp-response-table" aria-labelledby="smtpResponseTableTitle">
        <thead><tr>
          <th scope="col" data-smtp-i18n="smtpColumnBasic">SMTP</th><th scope="col" data-smtp-i18n="smtpColumnEnhanced">Enhanced</th>
          <th scope="col" data-smtp-i18n="smtpColumnMeaning">Meaning</th><th scope="col" data-smtp-i18n="smtpColumnCauses">Likely causes</th><th scope="col" data-smtp-i18n="smtpColumnFix">Suggested fixes</th>
        </tr></thead>
        <tbody id="smtpResponseTableBody"></tbody>
      </table>
    </div>
    <p id="smtpResponseNotice" class="smtp-reference-notice" data-smtp-i18n="smtpReferenceNotice"></p>
    <p class="smtp-reference-notice"><a href="https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml" target="_blank" rel="noopener noreferrer" data-smtp-i18n="smtpIanaReference">IANA status registry</a> &middot; <a href="https://learn.microsoft.com/troubleshoot/exchange/email-delivery/ndr/non-delivery-reports-in-exchange-online" target="_blank" rel="noopener noreferrer" data-smtp-i18n="smtpExchangeReference">Exchange Online NDR reference</a></p>
  </div>
</dialog>

<script nonce="__CSP_NONCE__">
const SMTP_RESPONSE_INPUT_LIMIT = 16000;
const SMTP_RESPONSE_RESULT_LIMIT = 50;

const SMTP_RESPONSE_SOURCES = {
  smtp: { label: 'RFC 5321', url: 'https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.3' },
  enhanced: { label: 'IANA / RFC', url: 'https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml' },
  auth: { label: 'RFC 4954', url: 'https://www.rfc-editor.org/rfc/rfc4954.html#section-6' },
  tls: { label: 'RFC 3207', url: 'https://www.rfc-editor.org/rfc/rfc3207.html#section-4' },
  nullMx: { label: 'RFC 7504', url: 'https://www.rfc-editor.org/rfc/rfc7504.html#section-3' },
  exchange: { label: 'Exchange Online', url: 'https://learn.microsoft.com/troubleshoot/exchange/email-delivery/ndr/non-delivery-reports-in-exchange-online' }
};

// Original troubleshooting summaries, based on the linked specifications.
// Tuple fields: code, meaning, likely causes, suggested fix, optional source.
const SMTP_BASIC_RESPONSES = new Map([
  ['211', 'System status', 'The server returned status or help information.', 'No error to fix. Continue the SMTP conversation.'],
  ['214', 'Help response', 'The server returned help for a command.', 'No error to fix. Use the advertised command syntax.'],
  ['220', 'Service ready', 'The SMTP service is ready, or STARTTLS is ready to begin.', 'Continue with EHLO, or complete the TLS handshake if this followed STARTTLS. This is not a delivery receipt.'],
  ['221', 'Connection closing', 'The server is closing the session, usually after QUIT.', 'No action is needed for a normal close. Check the preceding reply for the message outcome.'],
  ['235', 'Authentication succeeded', 'The server accepted the SMTP authentication exchange.', 'Continue with message submission. Authentication alone does not prove delivery.', 'auth'],
  ['250', 'Requested action accepted', 'The preceding command completed. After DATA, the server has accepted responsibility for the message.', 'Use message trace or delivery events to confirm the final outcome. Acceptance does not guarantee inbox placement.'],
  ['251', 'Recipient will be forwarded', 'The recipient is not local; the server will forward the message.', 'Confirm the forwarding address with the recipient before updating saved contact information.'],
  ['252', 'Recipient cannot be verified', 'The server does not verify the address but will attempt delivery.', 'Do not treat this as proof that the mailbox exists. Check the eventual delivery result.'],
  ['334', 'Authentication challenge', 'The server needs the next step of the AUTH exchange.', 'Let the SMTP client complete the supported authentication flow over a secure connection.', 'auth'],
  ['354', 'Ready for message data', 'The server accepted DATA and is waiting for the message content.', 'Let the SMTP client send the message and wait for the final reply. The message is not yet accepted.'],
  ['421', 'Service temporarily unavailable', 'Maintenance, overload, throttling, or a connection policy caused the server to close the session.', 'Check service health and sending limits. Let the sending service retry with backoff; avoid reconnecting in a tight loop.'],
  ['432', 'Authentication transition needed', 'In SMTP AUTH, the account needs a transition to the selected authentication mechanism. Providers may use this code differently.', 'Follow the authentication provider\'s migration procedure. Check the enhanced code and reply text for provider-specific throttling.', 'auth'],
  ['450', 'Mailbox temporarily unavailable', 'The mailbox may be busy, temporarily disabled, greylisted, or restricted by policy.', 'Allow the sender\'s retry schedule to run. For repeated failures, ask the recipient administrator to inspect the mailbox and policy.'],
  ['451', 'Temporary processing failure', 'The server encountered a local processing, directory, DNS, or policy evaluation problem.', 'Check the enhanced code and receiving service health. Have the responsible administrator resolve persistent processing failures.'],
  ['452', 'Insufficient resources', 'The server may lack storage or have reached its per-transaction recipient capacity.', 'Check the reply text. Free server storage or split recipient batches when the server reports too many recipients.'],
  ['454', 'Temporary authentication or TLS failure', 'The authentication backend or TLS service is temporarily unavailable.', 'Check the enhanced code, service health, and TLS configuration. Keep encryption enabled.', 'tls'],
  ['455', 'Parameters temporarily unsupported', 'The server cannot currently accommodate a MAIL FROM or RCPT TO parameter.', 'Use parameters advertised in EHLO and retry according to the sending service\'s policy.'],
  ['500', 'Command not recognized', 'The command is unsupported, malformed, or too long.', 'Check SMTP client configuration, line lengths, and the advertised EHLO capabilities.'],
  ['501', 'Invalid command arguments', 'A command argument, address, or parameter has invalid syntax.', 'Correct the envelope addresses and command parameters. Use a maintained SMTP client library.'],
  ['502', 'Command not implemented', 'The server recognizes the command but does not implement it.', 'Use supported commands and verify that the selected endpoint is the intended SMTP service.'],
  ['503', 'Commands out of sequence', 'A required earlier command is missing, or a transaction is already open.', 'Check the EHLO, authentication, MAIL FROM, RCPT TO, and DATA sequence in the SMTP client.'],
  ['504', 'Unsupported command parameter', 'The server does not support a requested parameter or authentication mechanism.', 'Use the mechanisms and extensions advertised by the server after EHLO and STARTTLS.'],
  ['521', 'Host does not accept mail', 'The destination host explicitly does not provide an SMTP mail service.', 'Verify the recipient domain and MX configuration with its administrator.', 'nullMx'],
  ['530', 'Authentication or STARTTLS required', 'The server requires authentication or a secure connection before the requested command.', 'Check the reply text; enable STARTTLS and the provider\'s supported authentication method. Do not disable TLS.', 'auth'],
  ['534', 'Authentication mechanism too weak', 'The selected authentication method does not satisfy server policy.', 'Use a stronger supported authentication method and a secure connection.', 'auth'],
  ['535', 'Authentication failed', 'Credentials, authorization, or the selected authentication flow were rejected.', 'Verify the account, application permissions, and supported authentication method in the provider console. Never paste passwords or tokens here.', 'auth'],
  ['538', 'Encryption required for authentication', 'The authentication mechanism requires an encrypted connection.', 'Configure STARTTLS or the provider\'s documented TLS submission endpoint before authentication.', 'auth'],
  ['550', 'Mailbox unavailable or action rejected', 'The address may not exist, access may be denied, or a recipient or relay policy may reject the request.', 'Use the enhanced code and original reply to distinguish an address problem from a policy or authentication failure.'],
  ['551', 'Recipient is not local', 'The server declined delivery and may have supplied a forwarding address.', 'Verify the replacement address with the recipient and correct routing or contact information.'],
  ['552', 'Storage or message limit exceeded', 'The mailbox quota or message size limit was exceeded. Older servers also use this for too many recipients.', 'Free mailbox space or reduce message size. If the text specifically says too many recipients, split the batch and retry those recipients.'],
  ['553', 'Mailbox name not allowed', 'An envelope address has invalid syntax or is not allowed by the receiving system.', 'Check sender and recipient addresses, permitted sender identities, and the enhanced status code.'],
  ['554', 'Transaction rejected', 'The message or connection was rejected; this broad code alone does not establish the cause.', 'Inspect the enhanced code and receiver\'s explanation for content, policy, authentication, or routing failures.'],
  ['555', 'Unsupported envelope parameters', 'A MAIL FROM or RCPT TO parameter is unrecognized or not implemented.', 'Remove unsupported parameters and use only extensions advertised by EHLO.'],
  ['556', 'Recipient domain does not accept mail', 'The recipient domain explicitly does not accept email, commonly through a null MX record.', 'Use a different confirmed recipient address. A null MX is intentional; do not replace it without the domain owner\'s approval.', 'nullMx']
].map(([code, meaning, causes, fix, source = 'smtp']) => [code, { meaning, causes, fix, source, translationKey: 'smtpBasic' + code }]));

// Class allowlists prevent a failure-only detail such as X.1.1 from becoming
// a misleading "recipient missing" explanation for the success code 2.1.1.
// Tuple fields: applicable classes, subject.detail, meaning, causes, fix.
const SMTP_ENHANCED_RESPONSES = new Map([
  ['245', '0.0', 'No additional status detail', 'The server provided only a broad outcome.', 'Use the full server reply and message trace to establish what happened.'],
  ['45', '1.0', 'Address-related failure', 'The sender or recipient address could not be used; no more specific detail was supplied.', 'Verify both envelope addresses and the receiving directory.'],
  ['5', '1.1', 'Recipient mailbox not found', 'The mailbox or alias does not exist, was removed, or was entered incorrectly.', 'Confirm the address with the recipient, correct spelling, and remove stale autocomplete entries. Ask the recipient administrator to verify aliases.'],
  ['5', '1.2', 'Recipient domain is invalid for mail', 'The destination domain does not exist or cannot accept mail.', 'Correct the domain spelling and have its owner check registration, MX records, and mail service configuration.'],
  ['5', '1.3', 'Invalid recipient address syntax', 'The recipient address is malformed.', 'Correct the envelope address, including the local part, @ separator, and domain.'],
  ['5', '1.4', 'Ambiguous recipient address', 'The receiving directory resolves the address to more than one recipient.', 'Ask the recipient administrator to correct conflicting aliases or directory entries.'],
  ['2', '1.5', 'Recipient address accepted', 'The receiving system accepted the specified address.', 'No address correction is indicated. Acceptance at this stage is not proof of final inbox delivery.'],
  ['5', '1.6', 'Recipient moved without forwarding', 'The former mailbox no longer accepts mail and has no forwarding destination.', 'Obtain the recipient\'s current address and update saved contacts.'],
  ['5', '1.7', 'Invalid sender address syntax', 'The envelope sender address is malformed.', 'Correct the MAIL FROM address and verify the application\'s sender configuration.'],
  ['45', '1.8', 'Sender domain cannot receive return mail', 'The sender domain is invalid for return mail. Exchange Online can also use 5.1.8 for a blocked outbound sender.', 'Check the envelope sender domain and DNS. If Exchange reports a bad outbound sender, investigate account compromise and use its restricted-entity recovery process.'],
  ['5', '1.10', 'Recipient domain publishes null MX', 'The standard meaning is that the recipient domain explicitly does not accept email. Exchange Online also uses 5.1.10 for a recipient not found in its directory.', 'Check the rejecting provider and full reply. For null MX, use a different recipient; for Exchange recipient-not-found, verify the mailbox and aliases.'],
  ['45', '2.0', 'Mailbox-related failure', 'A mailbox condition prevented delivery; no specific condition was supplied.', 'Ask the recipient administrator to inspect mailbox state, quota, and delivery restrictions.'],
  ['45', '2.1', 'Mailbox disabled', 'The mailbox exists but is not accepting messages.', 'Ask the recipient administrator to verify account state, licensing, and mailbox availability.'],
  ['45', '2.2', 'Mailbox full or quota exceeded', 'The recipient mailbox has reached its quota. Exchange Online may instead report a sender submission quota in the reply text.', 'For mailbox full, the recipient must free space or adjust quota. For submission quota, reduce sending and check provider limits and account security.'],
  ['5', '2.3', 'Recipient message-size limit exceeded', 'The message exceeds a per-mailbox size limit.', 'Reduce message and attachment size, allowing for MIME encoding overhead, or use an approved file-sharing link.'],
  ['45', '2.4', 'Mailing list expansion failed', 'The group or list could not be expanded into recipients.', 'Ask the list owner to correct membership or directory errors and check the group service.'],
  ['45', '3.0', 'Mail system failure', 'The destination service reported a general system problem.', 'Ask the receiving administrator to check service health, queues, and server diagnostics.'],
  ['4', '3.1', 'Mail system storage exhausted', 'The receiving system has exhausted shared storage rather than only one mailbox quota.', 'The receiving administrator must restore server capacity. Let the sending service retry with backoff.'],
  ['45', '3.2', 'Mail system is not accepting messages', 'The system is under maintenance, shutting down, overloaded, or otherwise refusing mail.', 'Check receiver service health and connection limits. A permanent reply requires correction before a new send.'],
  ['5', '3.3', 'Required mail feature unavailable', 'The destination or a gateway cannot support a requested feature.', 'Use supported message features or have the mail administrator correct the gateway configuration.'],
  ['5', '3.4', 'System message-size limit exceeded', 'The message exceeds a receiving server\'s maximum message size.', 'Reduce the encoded message size or use an approved file-sharing link. Check limits across the full delivery path.'],
  ['45', '3.5', 'Mail system misconfigured', 'A receiving or intermediate mail system is configured incorrectly.', 'Have its administrator inspect accepted domains, connectors, routing, and service configuration.'],
  ['45', '4.0', 'Network or routing failure', 'A connection or routing problem was reported without a specific detail.', 'Check destination MX and address records, network reachability, and mail routing.'],
  ['4', '4.1', 'Destination host did not answer', 'The destination may be offline, overloaded, or blocked by a firewall.', 'Check the receiving SMTP listener, MX targets, and firewall rules with the receiver\'s administrator.'],
  ['4', '4.2', 'Connection failed during delivery', 'A connection was established but timed out or broke before the transaction completed.', 'Check network stability, SMTP timeouts, TLS failures, and receiver service health.'],
  ['4', '4.3', 'Directory or DNS service unavailable', 'A directory or DNS lookup needed for routing failed.', 'Check authoritative DNS, resolver health, DNSSEC, and directory availability.'],
  ['45', '4.4', 'No usable mail route', 'The sender could not determine the next mail server or a configured route is invalid.', 'Verify MX and A/AAAA records, accepted domains, and connector or smart-host routing.'],
  ['4', '4.5', 'Mail system congested', 'Queues or delivery capacity are overloaded.', 'Reduce concurrency and sending rate, and let the mail service drain its queues.'],
  ['45', '4.6', 'Mail routing loop', 'Forwarding rules or connectors route the message repeatedly through the same systems.', 'Have the mail administrators trace the hops and remove the circular forwarding or connector route.'],
  ['45', '4.7', 'Delivery time expired', 'The message remained undelivered until its queue lifetime expired.', 'Inspect earlier delivery errors and fix the underlying problem. An expired message is no longer automatically retried and may need a new send.'],
  ['45', '5.0', 'Mail protocol failure', 'The SMTP exchange failed without a more specific protocol detail.', 'Inspect the sending client\'s SMTP sequence and the receiver\'s explanation.'],
  ['5', '5.1', 'Invalid or out-of-order command', 'A command is unsupported or was sent in the wrong SMTP state.', 'Check the SMTP sequence and advertised server capabilities.'],
  ['5', '5.2', 'SMTP syntax error', 'The receiver could not parse a command.', 'Correct command formatting and update the SMTP client library.'],
  ['45', '5.3', 'Too many recipients', 'The transaction exceeds the receiving service\'s recipient limit.', 'Split the recipient list into smaller batches within the provider\'s published limits. Do not resend to recipients already accepted.'],
  ['5', '5.4', 'Invalid SMTP arguments', 'A recognized command contains invalid or unsupported arguments.', 'Correct envelope addresses and use only negotiated SMTP extensions.'],
  ['5', '5.5', 'Protocol version mismatch', 'The communicating systems cannot agree on the required protocol features.', 'Update the SMTP client or gateway and check compatible server capabilities.'],
  ['45', '6.0', 'Message content or encoding problem', 'The message could not be handled because of its content representation.', 'Validate MIME headers, encodings, and attachments using the original receiver diagnostic.'],
  ['5', '6.1', 'Message media unsupported', 'A content type or encoding is unsupported by a receiving system.', 'Use supported MIME types and encodings or an approved file-sharing link.'],
  ['5', '6.2', 'Required conversion is prohibited', 'Delivery requires a content conversion that policy does not permit.', 'Send the message in a supported format or ask the administrator to review the applicable policy.'],
  ['5', '6.3', 'Required conversion is unavailable', 'A gateway cannot convert the message for the next hop.', 'Generate a compatible MIME message and verify gateway encoding capabilities.'],
  ['45', '6.5', 'Message conversion failed', 'A required content conversion could not be completed.', 'Check message encoding and the converting gateway for errors.'],
  ['5', '6.7', 'Internationalized address unsupported', 'Non-ASCII envelope addresses are not permitted on this delivery path.', 'Use an SMTPUTF8-capable path or an actual ASCII alias provided by the recipient. Do not simply strip address characters.'],
  ['5', '6.8', 'UTF-8 reply unavailable to this client', 'The server needs a UTF-8 reply that the client did not negotiate.', 'Use an SMTPUTF8-capable client and compatible mail route.'],
  ['5', '6.9', 'UTF-8 message cannot reach all recipients', 'One or more recipients cannot be reached through an SMTPUTF8-capable path.', 'Verify SMTPUTF8 support throughout the route and use confirmed compatible aliases when available.'],
  ['45', '7.0', 'Unspecified security or policy failure', 'A security restriction, authentication issue, or filtering policy prevented the action.', 'Read the full reply and have the responsible mail administrator inspect authentication and policy decisions.'],
  ['45', '7.1', 'Delivery restricted by policy', 'Possible causes include relay denial, recipient restrictions, filtering, or missing authentication. Temporary replies can also indicate greylisting.', 'Confirm the SMTP endpoint and authentication, recipient permissions, and sender reputation. Ask the receiving administrator about the specific policy; do not disable protections broadly.'],
  ['5', '7.2', 'Sending to this list is not permitted', 'The sender is not authorized to use the mailing list.', 'Ask the list owner to approve the sender or use an authorized address.'],
  ['5', '7.3', 'Secure message conversion unavailable', 'The gateway cannot perform a required secure-message conversion.', 'Use a mutually supported secure message format and consult the mail administrator.'],
  ['5', '7.4', 'Security feature unsupported', 'The receiving system cannot support a requested security feature.', 'Use a supported authentication or secure-message method without weakening transport security.'],
  ['45', '7.5', 'Cryptographic validation failed', 'A required key or certificate is missing or invalid. Providers may use this for TLS or MTA-STS certificate validation.', 'Check certificate validity, hostnames, trust chains, and the relevant message or transport security policy.'],
  ['5', '7.6', 'Cryptographic algorithm unsupported', 'The sender and receiver do not support a common required algorithm.', 'Update the clients or servers and select a mutually supported secure algorithm.'],
  ['45', '7.7', 'Message integrity check failed', 'Message content changed or a cryptographic integrity check failed.', 'Identify modifications in gateways or forwarding systems and validate signing configuration.'],
  ['5', '7.8', 'Authentication credentials rejected', 'The AUTH exchange used invalid or insufficient credentials.', 'Verify the account, OAuth configuration or supported credential method, application permissions, and service authentication settings.'],
  ['5', '7.9', 'Authentication method too weak', 'The selected authentication mechanism does not satisfy receiver policy.', 'Use a stronger method advertised by the server and keep TLS enabled.'],
  ['5', '7.10', 'Encrypted connection needed', 'The authentication mechanism requires a stronger privacy layer.', 'Establish TLS before authentication or use a stronger supported mechanism.'],
  ['5', '7.11', 'Authentication requires encryption', 'The selected authentication method cannot be used on an unencrypted connection.', 'Configure STARTTLS or the documented TLS endpoint before authentication.'],
  ['4', '7.12', 'Authentication transition required', 'The account must be transitioned before it can use the selected authentication mechanism.', 'Follow the authentication provider\'s documented account-transition procedure over a secure connection.'],
  ['5', '7.13', 'Account disabled or recipient restricted', 'The standard meaning is a disabled account. Exchange Online also uses this code for a public folder restricted to authenticated internal senders.', 'Check the rejecting provider and full reply. Ask the account administrator or public-folder owner to review the relevant restriction.'],
  ['5', '7.20', 'No passing DKIM signature', 'The message has no DKIM signature that the receiver can validate.', 'Enable DKIM on the actual sending service, publish the correct selector records, and check for message modifications after signing.'],
  ['5', '7.21', 'No acceptable DKIM signature', 'A DKIM signature passes but does not satisfy the receiver\'s policy.', 'Check the signing domain, algorithm, key strength, and receiver requirements.'],
  ['5', '7.22', 'DKIM signing domain does not match author', 'A passing DKIM signature does not match the message\'s From domain as required.', 'Configure the sending service to sign with an appropriate domain aligned with the visible From address.'],
  ['5', '7.23', 'SPF validation failed', 'The actual sending IP is not authorized by the envelope sender domain\'s SPF policy.', 'Verify the MAIL FROM domain and sending service. Publish one valid SPF record authorizing the service and stay within the DNS lookup limit.'],
  ['45', '7.24', 'SPF evaluation error', 'DNS failures, multiple SPF records, malformed terms, or excessive SPF lookups prevented evaluation.', 'Fix the specific DNS or SPF error. Check includes and redirects, retain one SPF record, and avoid exceeding ten DNS-querying terms.'],
  ['5', '7.25', 'Reverse DNS validation failed', 'The sending IP lacks acceptable PTR or matching forward DNS records.', 'Ask the sending IP owner to configure PTR and matching A/AAAA records. Align the sending host identity with the provider\'s requirements.'],
  ['45', '7.26', 'Message authentication checks failed', 'Multiple authentication checks failed. Providers commonly use this for SPF, DKIM, or DMARC-related rejection; the code alone does not identify which check failed.', 'Inspect Authentication-Results and the receiver\'s reply. Correct SPF authorization and DKIM signing, then verify alignment with the From domain for DMARC.'],
  ['5', '7.27', 'Sender domain publishes null MX', 'The sender domain explicitly does not accept return mail and the receiver rejects such senders.', 'Use an appropriate, verified envelope sender domain that can receive required return mail.'],
  ['45', '7.28', 'Abusive message flood suspected', 'The receiver considers this traffic part of a message flood.', 'Stop unintended sending, investigate account security, reduce volume, and follow the receiver\'s remediation process.'],
  ['5', '7.29', 'ARC validation failed', 'The message\'s Authenticated Received Chain could not be validated.', 'Check ARC signatures, sealing order, and message modifications in forwarding gateways.'],
  ['5', '7.30', 'Required TLS support unavailable', 'The message requires REQUIRETLS but the next hop does not support it.', 'Use a mail route supporting REQUIRETLS throughout and have the administrators resolve the capability mismatch.']
].flatMap(([classes, suffix, meaning, causes, fix]) => Array.from(classes, statusClass => [
  statusClass + '.' + suffix, { meaning, causes, fix, source: 'enhanced', translationKey: 'smtpEnhanced' + suffix }
])));

// These are documented provider usages, not universal SMTP definitions.
const SMTP_PROVIDER_RESPONSES = new Map([
  ['4.4.316', 'Remote connection refused', 'Exchange Online could not connect to the destination SMTP service.', 'Have the destination administrator check the listener, firewall, MX targets, and service availability.'],
  ['4.4.317', 'Remote TLS certificate not trusted', 'Exchange Online could not validate the destination certificate chain.', 'Have the receiver install a valid certificate and complete trusted chain on the SMTP endpoint.'],
  ['5.2.121', 'Recipient rate limit for this sender', 'Exchange Online limited messages from one sender to a particular recipient.', 'Reduce messages to that recipient and wait for capacity to recover before submitting a new message.'],
  ['5.2.122', 'Recipient receiving rate exceeded', 'The Exchange Online recipient exceeded its total receiving rate.', 'Coordinate with the recipient administrator and reduce automated traffic before a new send.'],
  ['5.4.1', 'Recipient or relay access denied', 'Exchange Online may not recognize the recipient or accept mail for the destination domain.', 'Verify the mailbox, aliases, directory synchronization, accepted domains, and MX or connector routing.'],
  ['5.4.14', 'Mail routing loop detected', 'Exchange Online detected circular forwarding or connector routing.', 'Trace message hops and correct the looping connector, accepted-domain, or forwarding configuration.'],
  ['5.6.11', 'Invalid message line endings', 'The message contains bare line feeds rather than required CRLF line endings.', 'Update the generating application or SMTP library to emit compliant message line endings.'],
  ['5.7.12', 'Recipient requires an internal sender', 'The Exchange Online recipient rejects unauthenticated or external senders.', 'Ask the recipient administrator to review the recipient\'s delivery restrictions and authorize the intended sender where appropriate.'],
  ['5.7.57', 'Client not authenticated for submission', 'An application or device using Exchange Online submission did not authenticate as required.', 'Verify the submission endpoint, STARTTLS, and supported authentication flow. Check account and tenant SMTP AUTH policy; do not enable anonymous relay.'],
  ['5.7.64', 'Relay connector could not identify tenant', 'The on-premises sending IP or certificate no longer matches the Exchange Online inbound connector.', 'Have the administrator verify the connector\'s approved IPs or TLS certificate identity and accepted domains.'],
  ['5.7.124', 'Sender not permitted for group', 'The sender is not on the distribution group\'s allowed-senders list.', 'Ask the group owner to review and authorize the intended sender.'],
  ['5.7.133', 'Group rejects external senders', 'The distribution group accepts only authenticated internal senders.', 'Ask the group owner to review the external-sender restriction.'],
  ['5.7.134', 'Mailbox rejects external senders', 'The mailbox is restricted to authenticated internal senders.', 'Ask the recipient administrator to review mailbox delivery restrictions.'],
  ['5.7.509', 'DMARC reject policy applied', 'The visible From domain failed DMARC and publishes a rejecting policy.', 'Correct aligned SPF or DKIM for the actual sending service. Investigate forwarding and do not remove DMARC protection as a blanket fix.'],
  ['5.7.520', 'Automatic external forwarding blocked', 'An Exchange Online outbound policy does not allow automatic external forwarding.', 'Have the administrator review the forwarding rule and security requirements. Use an approved destination or narrowly scoped exception only when justified.'],
  ['5.7.705', 'Sending tenant restricted', 'Microsoft detected suspicious outbound traffic and restricted the tenant.', 'Stop abusive traffic, investigate compromise or open relays, secure the accounts, then contact Microsoft support.'],
  ['5.7.708', 'Traffic from sending IP rejected', 'Microsoft restricted the tenant or its outbound traffic due to suspicious activity.', 'Investigate and remediate unwanted sending, then use Microsoft\'s documented support process.'],
  ['5.7.750', 'Sending from unregistered domains blocked', 'Exchange Online detected suspicious use of domains not provisioned in the tenant.', 'Add and verify legitimate sending domains and investigate unauthorized sending.']
].map(([code, meaning, causes, fix]) => [code, { meaning, causes, fix, source: 'exchange', translationKey: 'smtpProvider' + code }]));

const SMTP_RESPONSE_SUBJECTS = {
  '0': 'smtpSubjectStatus', '1': 'smtpSubjectAddress', '2': 'smtpSubjectMailbox', '3': 'smtpSubjectSystem',
  '4': 'smtpSubjectNetwork', '5': 'smtpSubjectProtocol', '6': 'smtpSubjectContent', '7': 'smtpSubjectSecurity'
};

function parseSmtpResponses(value) {
  const input = String(value || '');
  const responses = [];
  const seen = new Set();
  let truncated = input.length > SMTP_RESPONSE_INPUT_LIMIT;
  // Match protocol replies, not arbitrary three-digit values in dates, IPs,
  // hostnames or diagnostic prose. DSN Status/Diagnostic-Code fields are valid.
  for (const line of input.slice(0, SMTP_RESPONSE_INPUT_LIMIT).split(/\r\n?|\n/)) {
    const text = line.trim().replace(/^(?:Remote server returned|(?:The )?server response was|SMTP error|Error)\s*:?\s*['"]?/i, '');
    const reply = text.match(/^(?:(?:Diagnostic-Code\s*:\s*smtp\s*;|(?:SMTP(?:\s+(?:response|reply|code))?|S)\s*[:=>])\s*)?([2-5][0-5][0-9])(?=$|[\s-])/i);
    const status = text.match(/^(?:Status\s*:\s*)?([245]\.\d{1,3}\.\d{1,3})(?=$|[\s;:)])/i);
    const afterReply = reply ? text.slice(reply[0].length).replace(/^[\s-]+/, '') : '';
    const enhanced = reply
      ? afterReply.match(/^([245]\.\d{1,3}\.\d{1,3})(?=$|[\s;:)])/)
      : status;
    const smtpCode = reply ? reply[1] : null;
    const enhancedCode = enhanced ? enhanced[1] : null;
    if (!smtpCode && !enhancedCode) continue;
    const key = (smtpCode || '') + '|' + (enhancedCode || '');
    if (seen.has(key)) continue;
    if (responses.length >= SMTP_RESPONSE_RESULT_LIMIT) {
      truncated = true;
      break;
    }
    seen.add(key);
    responses.push({
      smtpCode,
      enhancedCode,
      classMismatch: !!(smtpCode && enhancedCode && smtpCode[0] !== enhancedCode[0])
    });
  }
  return { responses, truncated };
}

function localizeSmtpResponseEntry(entry) {
  if (!entry) return null;
  const localized = { ...entry };
  for (const field of ['meaning', 'causes', 'fix']) {
    const key = entry.translationKey + field[0].toUpperCase() + field.slice(1);
    const value = t(key);
    localized[field] = value === key ? entry[field] : value;
  }
  return localized;
}

function getSmtpResponseDetails(response) {
  const statusClass = (response.enhancedCode || response.smtpCode)[0];
  const basic = localizeSmtpResponseEntry(SMTP_BASIC_RESPONSES.get(response.smtpCode));
  const enhanced = localizeSmtpResponseEntry(SMTP_ENHANCED_RESPONSES.get(response.enhancedCode) || SMTP_PROVIDER_RESPONSES.get(response.enhancedCode));
  const entry = response.enhancedCode ? enhanced : basic;
  const subject = response.enhancedCode ? SMTP_RESPONSE_SUBJECTS[response.enhancedCode.split('.')[1]] : null;
  return {
    ...response,
    statusClass: response.classMismatch ? 'mismatch' : statusClass,
    known: !!entry,
    meaning: entry ? entry.meaning : t('smtpUnknownMeaning', { subject: t(subject || 'smtpGenericSubject') }),
    causes: entry ? entry.causes : t('smtpUnknownCauses'),
    fix: entry ? entry.fix : t('smtpUnknownFix'),
    source: entry ? entry.source : (response.enhancedCode ? 'enhanced' : 'smtp'),
    smtpMeaning: basic ? basic.meaning : null
  };
}

function getSmtpResponseReference() {
  return [
    ...Array.from(SMTP_BASIC_RESPONSES.keys(), smtpCode => ({ smtpCode, enhancedCode: null, classMismatch: false })),
    ...Array.from(new Set([...SMTP_ENHANCED_RESPONSES.keys(), ...SMTP_PROVIDER_RESPONSES.keys()]), enhancedCode => ({ smtpCode: null, enhancedCode, classMismatch: false }))
  ].map(getSmtpResponseDetails);
}

const SMTP_RESPONSE_STATUS = {
  '2': { label: 'smtpStatusSuccess', advice: 'smtpAdviceSuccess', tag: 'tag-pass' },
  '3': { label: 'smtpStatusContinue', advice: 'smtpAdviceContinue', tag: 'tag-info' },
  '4': { label: 'smtpStatusTemporary', advice: 'smtpAdviceTemporary', tag: 'tag-warn' },
  '5': { label: 'smtpStatusPermanent', advice: 'smtpAdvicePermanent', tag: 'tag-fail' },
  mismatch: { label: 'smtpStatusMismatch', advice: 'smtpAdviceMismatch', tag: 'tag-warn' }
};
const SMTP_COMMON_RESPONSES = ['250 2.0.0', '354', '421 4.3.2', '550 5.1.1', '552 5.2.2', '550 5.7.1', '550 5.7.26'];
let smtpResponseVisibleRows = [];

function filterSmtpResponseReference(query, statusClass) {
  const terms = String(query || '').toLowerCase().trim().split(/\s+/).filter(Boolean);
  return getSmtpResponseReference().filter(row => {
    if (statusClass && row.statusClass !== statusClass) return false;
    const text = [row.smtpCode, row.enhancedCode, row.meaning, row.causes, row.fix, SMTP_RESPONSE_SOURCES[row.source].label].join(' ').toLowerCase();
    return terms.every(term => text.includes(term));
  });
}

function buildSmtpResponseTableRows(rows) {
  const missing = '<span class="smtp-muted">' + escapeHtml(t('smtpNotProvided')) + '</span>';
  return rows.map(row => {
    const status = SMTP_RESPONSE_STATUS[row.statusClass];
    const source = SMTP_RESPONSE_SOURCES[row.source];
    const basicCode = row.smtpCode ? '<code>' + escapeHtml(row.smtpCode) + '</code>' : missing;
    const enhancedCode = row.enhancedCode ? '<code>' + escapeHtml(row.enhancedCode) + '</code>' : missing;
    const basicMeaning = row.smtpCode && row.enhancedCode && row.smtpMeaning
      ? '<span class="smtp-basic-meaning"><bdi dir="ltr">SMTP ' + escapeHtml(row.smtpCode) + '</bdi>: ' + escapeHtml(row.smtpMeaning) + '</span>' : '';
    const scope = !row.known ? t('smtpGenericDetail') : row.source === 'exchange' ? t('smtpProviderSpecific') : '';
    return `<tr>
      <td class="smtp-code-cell" dir="ltr">${basicCode}</td>
      <td class="smtp-code-cell" dir="ltr">${enhancedCode}</td>
      <td><span class="tag ${status.tag}">${escapeHtml(t(status.label))}</span>
        <strong class="smtp-meaning">${escapeHtml(row.meaning)}</strong>${basicMeaning}
        <span class="smtp-source">${scope ? escapeHtml(scope) + ' ' : ''}<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" dir="ltr">${escapeHtml(source.label)}</a></span>
      </td>
      <td>${escapeHtml(row.causes)}</td>
      <td><span>${escapeHtml(row.fix)}</span><p class="smtp-advice">${escapeHtml(t(status.advice))}</p></td>
    </tr>`;
  }).join('');
}

function formatSmtpResponseCopy(rows) {
  const headers = ['smtpColumnBasic', 'smtpColumnEnhanced', 'smtpColumnMeaning', 'smtpColumnCauses', 'smtpColumnFix'].map(key => t(key));
  return [headers.join('\t'), ...rows.map(row => {
    const status = SMTP_RESPONSE_STATUS[row.statusClass];
    return [row.smtpCode || t('smtpNotProvided'), row.enhancedCode || t('smtpNotProvided'),
      t(status.label) + ': ' + row.meaning, row.causes,
      row.fix + ' ' + t(status.advice) + ' ' + SMTP_RESPONSE_SOURCES[row.source].url].join('\t');
  })].join('\n');
}

function renderSmtpResponseLookup() {
  const dialog = document.getElementById('smtpResponseDialog');
  if (!dialog) return;
  const referenceMode = dialog.querySelector('input[name="smtpResponseMode"]:checked').value === 'reference';
  const input = document.getElementById('smtpResponseInput').value;
  const parsed = parseSmtpResponses(input);
  const examples = !referenceMode && !input.trim();
  smtpResponseVisibleRows = referenceMode
    ? filterSmtpResponseReference(document.getElementById('smtpReferenceSearch').value, document.getElementById('smtpReferenceStatus').value)
    : (examples ? SMTP_COMMON_RESPONSES.flatMap(value => parseSmtpResponses(value).responses) : parsed.responses).map(getSmtpResponseDetails);
  document.getElementById('smtpResponseForm').hidden = referenceMode;
  document.getElementById('smtpReferenceFilters').hidden = !referenceMode;
  document.getElementById('smtpResponseTableTitle').textContent = t(referenceMode ? 'smtpCodeReference' : examples ? 'smtpCommonResponses' : 'smtpDecodedResponses');
  document.getElementById('smtpResponseTableBody').innerHTML = buildSmtpResponseTableRows(smtpResponseVisibleRows);
  const hasRows = smtpResponseVisibleRows.length > 0;
  const empty = document.getElementById('smtpResponseEmpty');
  empty.hidden = hasRows;
  empty.textContent = t(referenceMode ? 'smtpNoReferenceMatches' : 'smtpNoCodeFound');
  document.getElementById('smtpResponseTableWrap').hidden = !hasRows;
  document.getElementById('smtpResponseCopy').disabled = !hasRows;
  document.getElementById('smtpResponseClear').disabled = !input;
  document.getElementById('smtpResponseLimit').hidden = referenceMode || !(parsed.truncated || input.length >= SMTP_RESPONSE_INPUT_LIMIT);
  document.getElementById('smtpResponseStatus').textContent = hasRows ? t('smtpResultCount', { count: smtpResponseVisibleRows.length }) : empty.textContent;
}

function applySmtpResponseLanguage() {
  document.querySelectorAll('[data-smtp-i18n]').forEach(element => {
    element.textContent = t(element.dataset.smtpI18n);
  });
  document.querySelectorAll('[data-smtp-title]').forEach(element => {
    element.title = t(element.dataset.smtpTitle);
    element.setAttribute('aria-label', element.title);
  });
  renderSmtpResponseLookup();
}

function initializeSmtpResponseTool() {
  if (window.self !== window.top) return;
  const dialog = document.getElementById('smtpResponseDialog');
  const launcher = document.getElementById('smtpResponseOpen');
  const input = document.getElementById('smtpResponseInput');
  document.querySelectorAll('[data-smtp-icon]').forEach(image => {
    image.src = getLucideIconUrl(image.dataset.smtpIcon);
  });
  applySmtpResponseLanguage();
  launcher.addEventListener('click', () => {
    renderSmtpResponseLookup();
    dialog.showModal();
    document.documentElement.classList.add('smtp-dialog-open');
    const referenceMode = dialog.querySelector('input[name="smtpResponseMode"]:checked').value === 'reference';
    document.getElementById(referenceMode ? 'smtpReferenceSearch' : 'smtpResponseInput').focus({ preventScroll: true });
  });
  document.getElementById('smtpResponseClose').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => {
    document.documentElement.classList.remove('smtp-dialog-open');
    launcher.focus({ preventScroll: true });
  });
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || event.isComposing) return;
    event.preventDefault();
    event.stopPropagation();
    dialog.close();
  });
  // Native dialogs keep focus contained; embedded browsers may need the explicit
  // Escape path above. Only a click outside the dialog bounds is a backdrop click.
  dialog.addEventListener('click', event => {
    if (event.target !== dialog) return;
    const bounds = dialog.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
  });
  document.getElementById('smtpResponseForm').addEventListener('submit', event => {
    event.preventDefault();
    renderSmtpResponseLookup();
  });
  input.addEventListener('input', renderSmtpResponseLookup);
  document.getElementById('smtpReferenceSearch').addEventListener('input', renderSmtpResponseLookup);
  document.getElementById('smtpReferenceStatus').addEventListener('change', renderSmtpResponseLookup);
  dialog.querySelectorAll('input[name="smtpResponseMode"]').forEach(radio => radio.addEventListener('change', renderSmtpResponseLookup));
  document.getElementById('smtpResponseClear').addEventListener('click', () => {
    input.value = '';
    renderSmtpResponseLookup();
    input.focus();
  });
  document.getElementById('smtpResponseCopy').addEventListener('click', async () => {
    if (!smtpResponseVisibleRows.length) return;
    try {
      await navigator.clipboard.writeText(formatSmtpResponseCopy(smtpResponseVisibleRows));
      document.getElementById('smtpResponseStatus').textContent = t('smtpResultsCopied');
    } catch {
      document.getElementById('smtpResponseStatus').textContent = t('smtpCopyUnavailable');
    }
  });
}

document.addEventListener('DOMContentLoaded', initializeSmtpResponseTool);
</script>
</body>
</html>
'@