<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// ============================================================================
// 1. CONFIGURATION
// ============================================================================
$config = [
    // Target inbox where lead notifications will be sent
    'to_email'           => 'nextravox@gmail.com',
    'to_name'            => 'Nextravox Tech',

    // Hostinger CyberPanel sender address
    'from_email'         => 'automail@nextravox.com',
    'from_name'          => 'Nextravox Website Inquiry',

    // Built-in SMTP Settings (Supports AUTH PLAIN & AUTH LOGIN automatically)
    'use_smtp'           => true,
    'smtp_host'          => 'mail.nextravox.com',
    'smtp_port'          => 587,
    'smtp_username'      => 'automail@nextravox.com',
    'smtp_password'      => 'IBe51OC!@3312ABOP#n5B5edbD',
    'smtp_encryption'    => 'tls',   // 'tls' (port 587 STARTTLS) or 'ssl' (port 465)
    'smtp_verify_ssl'    => false,   // Set to true after issuing MailServer SSL in CyberPanel

    // Testing & Rate Limiting Settings
    'testing_mode'       => false,    // Set to false after testing (hides technical SMTP errors from visitors)
    'rate_limit_enabled' => true,   // Set to true after testing to enable 3/hour IP rate limit
    'rate_limit_max'     => 3,
    'rate_limit_window'  => 3600,
    'rate_limit_salt'    => 'nxv_2026_penang_rate_salt_change_me',
    'data_dir'           => __DIR__ . '/data',

    // Anti-bot minimum fill time in seconds (0 during testing; set to 2 after testing)
    'min_fill_seconds'   => 2,
];

// ============================================================================
// 2. ONLY ALLOW POST REQUESTS
// ============================================================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Method not allowed.'
    ]);
    exit;
}

// Support both FormData ($_POST) and JSON payloads
$input = $_POST;
if (empty($input)) {
    $rawBody = file_get_contents('php://input');
    $decoded = json_decode($rawBody ?: '', true);
    if (is_array($decoded)) {
        $input = $decoded;
    }
}

// ============================================================================
// 3. HONEYPOT SPAM TRAP (SILENT FAKE SUCCESS FOR BOTS)
// ============================================================================
$honeypot = trim((string)($input['company_website'] ?? ''));
if ($honeypot !== '') {
    http_response_code(200);
    echo json_encode([
        'status'  => 'success',
        'message' => 'Thank you! Your inquiry has been received.'
    ]);
    exit;
}

// ============================================================================
// 4. SUBMISSION SPEED CHECK
// ============================================================================
$minFillSeconds = (int)$config['min_fill_seconds'];
if ($minFillSeconds > 0) {
    $formRenderedAt = (int)($input['form_ts'] ?? 0);
    $now = time();
    if ($formRenderedAt <= 0 || ($now - $formRenderedAt) < $minFillSeconds) {
        http_response_code(400);
        echo json_encode([
            'status'  => 'error',
            'message' => 'Form submitted too quickly. Please wait a moment and try again.'
        ]);
        exit;
    }
}

// ============================================================================
// 5. IP-BASED RATE LIMITING (TOGGLED VIA 'rate_limit_enabled')
// ============================================================================
function getClientIpAddress(): string
{
    $candidates = [
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
    ];

    foreach ($candidates as $ip) {
        $ip = trim((string)$ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return '0.0.0.0';
}

function checkAndRecordRateLimit(string $ip, array $config): array
{
    $dataDir = $config['data_dir'];
    if (!is_dir($dataDir)) {
        @mkdir($dataDir, 0750, true);
    }

    // Protect data directory from direct web access
    $htaccessFile = $dataDir . '/.htaccess';
    if (!file_exists($htaccessFile)) {
        @file_put_contents($htaccessFile, "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n");
    }
    $indexGuard = $dataDir . '/index.php';
    if (!file_exists($indexGuard)) {
        @file_put_contents($indexGuard, "<?php http_response_code(403); exit;");
    }

    $logFile = $dataDir . '/rate_limit.json';
    $fp = @fopen($logFile, 'c+');
    if (!$fp) {
        return ['allowed' => true, 'retry_after' => 0];
    }

    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $records = json_decode($raw ?: '{}', true);
    if (!is_array($records)) {
        $records = [];
    }

    $now = time();
    $window = (int)$config['rate_limit_window'];
    $maxRequests = (int)$config['rate_limit_max'];
    $ipHash = hash('sha256', $ip . $config['rate_limit_salt']);

    // Purge expired timestamps across all IPs
    foreach ($records as $hashKey => $timestamps) {
        if (!is_array($timestamps)) {
            unset($records[$hashKey]);
            continue;
        }
        $valid = array_values(array_filter($timestamps, static fn($ts) => ($now - (int)$ts) < $window));
        if (empty($valid)) {
            unset($records[$hashKey]);
        } else {
            $records[$hashKey] = $valid;
        }
    }

    $currentTimestamps = $records[$ipHash] ?? [];
    if (count($currentTimestamps) >= $maxRequests) {
        $oldest = min($currentTimestamps);
        $retryAfter = max(1, $window - ($now - (int)$oldest));

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($records, JSON_PRETTY_PRINT));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        return ['allowed' => false, 'retry_after' => $retryAfter];
    }

    $currentTimestamps[] = $now;
    $records[$ipHash] = $currentTimestamps;

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($records, JSON_PRETTY_PRINT));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return ['allowed' => true, 'retry_after' => 0];
}

$clientIp = getClientIpAddress();

if (!empty($config['rate_limit_enabled'])) {
    $rateCheck = checkAndRecordRateLimit($clientIp, $config);
    if (!$rateCheck['allowed']) {
        $minutesLeft = (int)ceil($rateCheck['retry_after'] / 60);
        http_response_code(429);
        echo json_encode([
            'status'      => 'rate_limited',
            'retry_after' => $rateCheck['retry_after'],
            'message'     => "Too many inquiries from your network. Please try again in about {$minutesLeft} minute(s) or message us directly on WhatsApp."
        ]);
        exit;
    }
}

// ============================================================================
// 6. VALIDATE & SANITIZE FORM FIELDS
// ============================================================================
function cleanSingleLine(string $value, int $maxLength = 150): string
{
    $value = str_replace(["\r", "\n", "\0"], ' ', trim($value));
    $value = strip_tags($value);
    return mb_substr($value, 0, $maxLength, 'UTF-8');
}

$name    = cleanSingleLine((string)($input['name'] ?? ''), 100);
$email   = cleanSingleLine((string)($input['email'] ?? ''), 150);
$phone   = cleanSingleLine((string)($input['phone'] ?? ''), 40);
$service = cleanSingleLine((string)($input['service'] ?? ''), 120);
$lang    = cleanSingleLine((string)($input['lang'] ?? 'en'), 10);
$message = trim(strip_tags((string)($input['message'] ?? '')));
$message = mb_substr($message, 0, 3000, 'UTF-8');

if ($name === '' || $email === '' || $phone === '' || $service === '' || $message === '') {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Please complete all required fields before submitting.'
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Please enter a valid email address.'
    ]);
    exit;
}

// ============================================================================
// 7. BUILD EMAIL CONTENT
// ============================================================================
date_default_timezone_set('Asia/Kuala_Lumpur');
$submittedTime = date('d M Y, h:i A (MYT)');

$safeName    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$safeEmail   = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$safePhone   = htmlspecialchars($phone, ENT_QUOTES, 'UTF-8');
$safeService = htmlspecialchars($service, ENT_QUOTES, 'UTF-8');
$safeLang    = htmlspecialchars(strtoupper($lang), ENT_QUOTES, 'UTF-8');
$safeIp      = htmlspecialchars($clientIp, ENT_QUOTES, 'UTF-8');
$safeMessage = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));

$waDigits = preg_replace('/[^0-9]/', '', $phone);
if (strpos($waDigits, '0') === 0) {
    $waDigits = '6' . $waDigits;
}
$waQuickLink = $waDigits !== '' ? "https://wa.me/{$waDigits}" : '';

$subject = "[Nextravox Lead] {$service} — {$name}";

$htmlBody = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>New Website Inquiry</title>
</head>
<body style="margin:0;padding:0;background-color:#020617;font-family:Arial,Helvetica,sans-serif;color:#e2e8f0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#020617;padding:24px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background-color:#0f172a;border:1px solid #1e293b;border-radius:16px;overflow:hidden;">
          <tr>
            <td style="background:linear-gradient(135deg,#135bec,#06b6d4);padding:20px 24px;color:#ffffff;">
              <h2 style="margin:0;font-size:20px;">New Lead Inquiry — Nextravox Tech</h2>
              <p style="margin:6px 0 0;font-size:13px;opacity:0.9;">Received on {$submittedTime}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:24px;">
              <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;font-size:14px;">
                <tr>
                  <td width="150" style="color:#94a3b8;border-bottom:1px solid #1e293b;"><strong>Client Name:</strong></td>
                  <td style="color:#ffffff;border-bottom:1px solid #1e293b;">{$safeName}</td>
                </tr>
                <tr>
                  <td style="color:#94a3b8;border-bottom:1px solid #1e293b;"><strong>Email:</strong></td>
                  <td style="color:#38bdf8;border-bottom:1px solid #1e293b;"><a href="mailto:{$safeEmail}" style="color:#38bdf8;text-decoration:none;">{$safeEmail}</a></td>
                </tr>
                <tr>
                  <td style="color:#94a3b8;border-bottom:1px solid #1e293b;"><strong>Phone / WhatsApp:</strong></td>
                  <td style="color:#ffffff;border-bottom:1px solid #1e293b;">{$safePhone}</td>
                </tr>
                <tr>
                  <td style="color:#94a3b8;border-bottom:1px solid #1e293b;"><strong>Service Needed:</strong></td>
                  <td style="color:#22d3ee;font-weight:bold;border-bottom:1px solid #1e293b;">{$safeService}</td>
                </tr>
                <tr>
                  <td style="color:#94a3b8;border-bottom:1px solid #1e293b;"><strong>Site Language:</strong></td>
                  <td style="color:#cbd5e1;border-bottom:1px solid #1e293b;">{$safeLang}</td>
                </tr>
              </table>

              <div style="margin-top:20px;padding:16px;background-color:#020617;border:1px solid #1e293b;border-radius:10px;">
                <p style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;">Project Details / Message</p>
                <div style="font-size:14px;line-height:1.6;color:#f8fafc;">{$safeMessage}</div>
              </div>
HTML;

if ($waQuickLink !== '') {
    $htmlBody .= <<<HTML
              <div style="margin-top:22px;text-align:center;">
                <a href="{$waQuickLink}" style="display:inline-block;padding:12px 24px;background-color:#25D366;color:#ffffff;font-weight:bold;text-decoration:none;border-radius:999px;font-size:14px;">Reply Directly via WhatsApp</a>
              </div>
HTML;
}

$htmlBody .= <<<HTML
            </td>
          </tr>
          <tr>
            <td style="padding:14px 24px;background-color:#020617;color:#64748b;font-size:12px;text-align:center;">
              Sent via {$config['from_email']} • Client IP: {$safeIp}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

// ============================================================================
// 8. NATIVE PHP SMTP SENDER (AUTO-DETECTS AUTH PLAIN & AUTH LOGIN)
// ============================================================================
function encodeMimeHeader(string $text): string
{
    if (preg_match('/[^\x20-\x7E]/', $text)) {
        return '=?UTF-8?B?' . base64_encode($text) . '?=';
    }
    if (preg_match('/[",:;<>@\(\)\[\]\\\\]/', $text)) {
        return '"' . addcslashes($text, '"\\') . '"';
    }
    return $text;
}

function readSmtpResponse($socket): array
{
    $response = '';
    $code = 0;
    while (($line = fgets($socket, 515)) !== false) {
        $response .= $line;
        if (strlen($line) >= 4 && $line[3] === ' ') {
            $code = (int)substr($line, 0, 3);
            break;
        }
    }
    return [$code, trim($response)];
}

function sendSmtpCommand($socket, string $command, array $expectedCodes, bool $maskLog = false): string
{
    fwrite($socket, $command . "\r\n");
    [$code, $response] = readSmtpResponse($socket);
    if (!in_array($code, $expectedCodes, true)) {
        $label = $maskLog ? 'AUTH ***' : $command;
        throw new \RuntimeException("SMTP command failed [{$label}] -> {$response}");
    }
    return $response;
}

function sendViaNativeSmtp(array $config, string $replyToEmail, string $replyToName, string $subject, string $htmlBody): void
{
    $host       = (string)$config['smtp_host'];
    $port       = (int)$config['smtp_port'];
    $encryption = strtolower((string)$config['smtp_encryption']);
    $username   = (string)$config['smtp_username'];
    $password   = (string)$config['smtp_password'];
    $fromEmail  = (string)$config['from_email'];
    $fromName   = (string)$config['from_name'];
    $toEmail    = (string)$config['to_email'];
    $toName     = (string)$config['to_name'];
    $verifySsl  = (bool)($config['smtp_verify_ssl'] ?? false);

    $contextOptions = [
        'ssl' => [
            'verify_peer'       => $verifySsl,
            'verify_peer_name'  => $verifySsl,
            'allow_self_signed' => !$verifySsl,
        ],
    ];
    $context = stream_context_create($contextOptions);

    $remote = ($encryption === 'ssl') ? "ssl://{$host}:{$port}" : "tcp://{$host}:{$port}";
    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);

    if (!$socket) {
        throw new \RuntimeException("Could not connect to SMTP server {$remote} ({$errno}: {$errstr})");
    }

    stream_set_timeout($socket, 15);

    try {
        [$greetCode, $greetMsg] = readSmtpResponse($socket);
        if ($greetCode !== 220) {
            throw new \RuntimeException("Unexpected SMTP greeting: {$greetMsg}");
        }

        $ehloDomain = $_SERVER['SERVER_NAME'] ?? 'nextravox.com';
        $ehloCaps = sendSmtpCommand($socket, "EHLO {$ehloDomain}", [250]);

        if ($encryption === 'tls') {
            sendSmtpCommand($socket, 'STARTTLS', [220]);
            $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }
            if (!@stream_socket_enable_crypto($socket, true, $cryptoMethod)) {
                throw new \RuntimeException('STARTTLS encryption handshake failed.');
            }
            $ehloCaps = sendSmtpCommand($socket, "EHLO {$ehloDomain}", [250]);
        }

        // CyberPanel Dovecot advertises AUTH PLAIN; use PLAIN if supported, else fallback to LOGIN
        if (preg_match('/250[- ]AUTH\b.*\bPLAIN\b/i', $ehloCaps)) {
            $plainToken = base64_encode("\0" . $username . "\0" . $password);
            sendSmtpCommand($socket, "AUTH PLAIN {$plainToken}", [235], true);
        } else {
            sendSmtpCommand($socket, 'AUTH LOGIN', [334]);
            sendSmtpCommand($socket, base64_encode($username), [334], true);
            sendSmtpCommand($socket, base64_encode($password), [235], true);
        }

        sendSmtpCommand($socket, "MAIL FROM:<{$fromEmail}>", [250]);
        sendSmtpCommand($socket, "RCPT TO:<{$toEmail}>", [250, 251]);
        sendSmtpCommand($socket, 'DATA', [354]);

        $domainPart = substr(strrchr($fromEmail, '@') ?: '@nextravox.com', 1);
        $messageId  = '<' . bin2hex(random_bytes(16)) . '@' . $domainPart . '>';

        $headers = [
            'Date: ' . date('r'),
            'Message-ID: ' . $messageId,
            'From: ' . encodeMimeHeader($fromName) . " <{$fromEmail}>",
            'To: ' . encodeMimeHeader($toName) . " <{$toEmail}>",
            'Reply-To: ' . encodeMimeHeader($replyToName) . " <{$replyToEmail}>",
            'Subject: ' . encodeMimeHeader($subject),
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'Content-Transfer-Encoding: base64',
        ];

        $encodedBody = chunk_split(base64_encode($htmlBody));
        $rawEmail = implode("\r\n", $headers) . "\r\n\r\n" . $encodedBody . "\r\n.";

        sendSmtpCommand($socket, $rawEmail, [250]);
        @fwrite($socket, "QUIT\r\n");
    } finally {
        @fclose($socket);
    }
}

$sent = false;
$errorDetail = '';

if (!empty($config['use_smtp'])) {
    try {
        sendViaNativeSmtp($config, $email, $name, $subject, $htmlBody);
        $sent = true;
    } catch (\Throwable $e) {
        error_log('Nextravox SMTP Error: ' . $e->getMessage());
        $errorDetail = $e->getMessage();
        $sent = false;
    }
} else {
    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=UTF-8',
        'From: ' . $config['from_name'] . ' <' . $config['from_email'] . '>',
        'Reply-To: ' . $name . ' <' . $email . '>',
        'X-Mailer: PHP/' . phpversion(),
    ];
    $envelopeSender = '-f' . $config['from_email'];
    $sent = @mail($config['to_email'], $encodedSubject, $htmlBody, implode("\r\n", $headers), $envelopeSender);
}

if ($sent) {
    http_response_code(200);
    echo json_encode([
        'status'  => 'success',
        'message' => 'Thank you! Your message has been sent. Kai will get back to you shortly.'
    ]);
} else {
    http_response_code(500);
    $publicMessage = 'Unable to send email right now. Please reach out directly via WhatsApp (+6014-288 0514).';
    if (!empty($config['testing_mode']) && $errorDetail !== '') {
        $publicMessage .= ' [SMTP Debug: ' . $errorDetail . ']';
    }
    echo json_encode([
        'status'  => 'error',
        'message' => $publicMessage
    ]);
}