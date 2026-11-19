<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
$config = [
    'to_email'          => 'nextravox@gmail.com',
    'to_name'           => 'Nextravox Tech',

    // Hostinger CyberPanel sender address
    'from_email'        => 'automail@nextravox.com',
    'from_name'         => 'Nextravox Website Inquiry',

    // Optional SMTP Settings (Set 'use_smtp' => true if you install PHPMailer)
    'use_smtp'          => true,
    'smtp_host'         => 'mail.nextravox.com',
    'smtp_port'         => 587,
    'smtp_username'     => 'automail@nextravox.com',
    'smtp_password'     => 'IBe51OC#n5B5edbD',
    'smtp_encryption'   => 'tls', // 'tls' (port 587) or 'ssl' (port 465)

    'rate_limit_max'    => 3,
    'rate_limit_window' => 3600,
    'rate_limit_salt'   => 'nxv_2026_penang_rate_salt_change_me',
    'data_dir'          => __DIR__ . '/data',

    // Anti-bot minimum fill time in seconds
    'min_fill_seconds'  => 2,
];

// ============================================================================
// 2. ONLY ALLOW POST REQUESTS
// ===============================V=============================================
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
// 4. SUBMISSION SPEED CHECK (REJECT INSTANT BOT POSTS < 2 SECONDS)
// ============================================================================
$formRenderedAt = (int)($input['form_ts'] ?? 0);
$now = time();
if ($formRenderedAt <= 0 || ($now - $formRenderedAt) < $config['min_fill_seconds']) {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Form submitted too quickly. Please wait a moment and try again.'
    ]);
    exit;
}

// ============================================================================
// 5. IP-BASED RATE LIMITING (MAX 3 SUBMISSIONS PER HOUR)
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

    // Protect data directory from direct web access (Apache & OpenLiteSpeed compatible)
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
// 7. BUILD EMAIL CONTENT & SEND
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

// Create clean WhatsApp quick-reply link
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
              Sent via {$config['from_email']} • Protected by Nextravox Honeypot &amp; Rate Limiter (Client IP: {$safeIp})
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

$sent = false;

// Optional PHPMailer SMTP path if enabled and library exists
if ($config['use_smtp']) {
    $autoloadPaths = [
        __DIR__ . '/vendor/autoload.php',
        __DIR__ . '/phpmailer/src/PHPMailer.php',
    ];
    foreach ($autoloadPaths as $path) {
        if (file_exists($path)) {
            require_once $path;
            break;
        }
    }
    if (file_exists(__DIR__ . '/phpmailer/src/SMTP.php')) {
        require_once __DIR__ . '/phpmailer/src/SMTP.php';
        require_once __DIR__ . '/phpmailer/src/Exception.php';
    }

    if (class_exists('\PHPMailer\PHPMailer\PHPMailer')) {
        try {
            $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
            $mail->isSMTP();
            $mail->Host       = $config['smtp_host'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $config['smtp_username'];
            $mail->Password   = $config['smtp_password'];
            $mail->SMTPSecure = $config['smtp_encryption'];
            $mail->Port       = (int)$config['smtp_port'];
            $mail->CharSet    = 'UTF-8';

            $mail->setFrom($config['from_email'], $config['from_name']);
            $mail->addAddress($config['to_email'], $config['to_name']);
            $mail->addReplyTo($email, $name);

            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $htmlBody;
            $mail->AltBody = "New Inquiry from {$name} ({$email} / {$phone})\nService: {$service}\n\nMessage:\n{$message}";

            $sent = $mail->send();
        } catch (\Throwable $e) {
            error_log('Nextravox SMTP Error: ' . $e->getMessage());
            $sent = false;
        }
    }
}

// Default CyberPanel Postfix mail() with -f envelope sender for SPF/DKIM alignment
if (!$sent) {
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
    echo json_encode([
        'status'  => 'error',
        'message' => 'Unable to send email right now. Please reach out directly via WhatsApp (+6014-288 0514).'
    ]);
}