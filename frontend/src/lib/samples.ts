export const SAMPLES = {
  clean: `From: "GitHub" <noreply@github.com>
Subject: Your weekly digest
Authentication-Results: spf=pass dkim=pass dmarc=pass

Hi Timothy, here's what happened in your repositories this week.
https://github.com/notifications`,
  phishing: `From: "Chase Bank" <alerts@chase-secure.co>
Subject: URGENT: Your account has been suspended
Authentication-Results: spf=fail dkim=fail dmarc=fail

Dear customer, verify your account within 24 hours or it will be suspended.
[[LINK https://chase.com http://192.168.1.99/login]]
Confirm your BVN and OTP here: https://bit.ly/chase-verify`,
  borderline: `From: "Kuda Bank" <notice@notice-pay.com>
Subject: Action needed on your card
Authentication-Results: spf=softfail dkim=pass

Hello, please review a recent card change immediately.
https://notice-pay.com/review`,
};
