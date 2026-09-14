const nodemailer = require('nodemailer');

let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendOtpEmail(to, code, purpose) {
  const subject = purpose === 'reset'
    ? 'Mbata Agent - Rejesha Password (OTP)'
    : 'Mbata Agent - Thibitisha Akaunti (OTP)';
  const text = `Msimbo wako wa OTP ni: ${code}\nUtakuwa halali kwa dakika 10.\nKama hukuomba hili, puuza email hii.`;

  if (!transporter) {
    // SMTP haijawekwa - andika OTP kwenye logs ili maendeleo yasisimame.
    console.log(`[OTP - SMTP HAIJAWEKWA] Email: ${to} | Purpose: ${purpose} | Code: ${code}`);
    return;
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text
  });
}

module.exports = { sendOtpEmail };
