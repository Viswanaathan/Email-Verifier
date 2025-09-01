# Email-Verifier
A responsive Flask web app that verifies email addresses for format, domain MX records, and SMTP reachability. Features a modern UI with dark/light mode toggle, animated landing page, and scrollable cards explaining purpose, audience, and result meanings. Ideal for devs and analysts.
📌 Project Overview
A responsive Flask-based web app to verify email addresses.

Checks for format validity, domain MX records, and SMTP mailbox reachability.

Designed with a modern, animated UI and dark/light mode toggle.

🎯 Why This Tool Is Needed
Prevents sending emails to invalid or unreachable addresses.

Helps recruiters, developers, and analysts validate user data before onboarding.

Reduces bounce rates and improves email deliverability.

Useful for cybersecurity workflows and governance-grade systems.

✨ Features
Email format validation using regex.

Domain MX record lookup via DNS.

SMTP-level mailbox verification (non-intrusive).

Animated landing page with scrollable cards.

Dark/light mode toggle with smooth transitions.

Responsive design for desktop and mobile.

Clear result messages with icons and color cues.

All-in-one Python file for easy deployment and demo.

🛠️ Technologies Used
Flask – Web framework for routing and rendering.

dnspython – For DNS MX record lookups.

smtplib – To simulate email delivery and check mailbox existence.

HTML/CSS – For layout, styling, and animations.

JavaScript – For dark/light mode toggle.

👥 Who It's For
Developers building secure onboarding flows.

Cybersecurity analysts validating user identities.

HR teams verifying candidate contact info.

Students and educators learning email protocols.

Anyone needing a clean, demo-ready email verification tool.
